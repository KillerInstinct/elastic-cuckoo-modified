# Copyright (C) 2010-2015 Cuckoo Foundation., Jpalanco (jose.palanco@drainware.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import os
import time

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    from elasticsearch import Elasticsearch
    HAVE_ELASTICSEARCH = True
except ImportError:
    HAVE_ELASTICSEARCH = False

class ElasticsearchDB(Report):
    """Stores report in Elastic Search."""

    # Elasticsearch schema version, used for data migration.
    SCHEMA_VERSION = "1"

    def connect(self):
        """Connects to Elasticsearch database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        self.es = Elasticsearch(
            hosts = [{
                'host': self.options.get("host", "127.0.0.1"),
                'port': self.options.get("port", 9200),
            }],
            timeout = 60
        )
        ts = time.time()

        index_prefix  = self.options.get("index", "cuckoo-*")

        self.es = Elasticsearch()
        self.index_name = '{0}-{1}'.format(index_prefix, datetime.datetime.fromtimestamp(ts).strftime('%Y.%m.%d'))

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to Elasticsearch.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_ELASTICSEARCH:
            raise CuckooDependencyError("Unable to import elasticsearch "
                                        "(install with `pip install elasticsearch`)")

        self.connect()

        # TODO: Set elasticsearch schema version.

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = dict(results)
        if not "network" in report:
            report["network"] = {}

        # Store chunks of API calls in a different collection and reference
        # those chunks back in the report. In this way we should defeat the
        # issue with the oversized reports exceeding Elasticsearch's boundaries.
        # Also allows paging of the reports.
        if "behavior" in report and "processes" in report["behavior"]:
            new_processes = []
            for process in report["behavior"]["processes"]:
                new_process = dict(process)

                chunk = []
                chunks_ids = []
                # Loop on each process call.
                for index, call in enumerate(process["calls"]):
                    # If the chunk size is 100 or if the loop is completed then
                    # store the chunk in Elastcisearch.
                    if len(chunk) == 100:
                        to_insert = {"pid": process["process_id"],
                                     "calls": chunk}
                        pchunk = self.es.index(index=self.index_name, doc_type="calls", body=to_insert)
                        chunk_id = pchunk['_id']
                        chunks_ids.append(chunk_id)
                        # Reset the chunk.
                        chunk = []

                    # Append call to the chunk.
                    chunk.append(call)

                # Store leftovers.
                if chunk:
                    to_insert = {"pid": process["process_id"], "calls": chunk}
                    pchunk = self.es.index(index=self.index_name, doc_type="calls", body=to_insert)
                    chunk_id = pchunk['_id']
                    chunks_ids.append(chunk_id)

                # Add list of chunks.
                new_process["calls"] = chunks_ids
                new_processes.append(new_process)

            # Store the results in the report.
            report["behavior"] = dict(report["behavior"])
            report["behavior"]["processes"] = new_processes

        # Other info we want Quick access to from the web UI
        if results.has_key("virustotal") and results["virustotal"] and results["virustotal"].has_key("positives") and results["virustotal"].has_key("total"):
            report["virustotal_summary"] = "%s/%s" % (results["virustotal"]["positives"],results["virustotal"]["total"])
        if results.has_key("suricata") and results["suricata"]:
            if results["suricata"].has_key("tls") and len(results["suricata"]["tls"]) > 0:
                report["suri_tls_cnt"] = len(results["suricata"]["tls"])
            if results["suricata"] and results["suricata"].has_key("alerts") and len(results["suricata"]["alerts"]) > 0:
                report["suri_alert_cnt"] = len(results["suricata"]["alerts"])
            if results["suricata"].has_key("files") and len(results["suricata"]["files"]) > 0:
                report["suri_file_cnt"] = len(results["suricata"]["files"])
            if results["suricata"].has_key("http") and len(results["suricata"]["http"]) > 0:
                report["suri_http_cnt"] = len(results["suricata"]["http"])

        # Store the report and retrieve its object id.
        self.es.index(index=self.index_name, doc_type="analysis", id=results["info"]["id"], body=report)
