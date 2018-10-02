#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from haveibeenpwnd import check_email, list_to_print_string

class haveibeenpwnedAnalyzer(Analyzer):
    """

    """

    def __init__(self):
        Analyzer.__init__(self)
        self.email = ''
        self.results = dict()

    def summary(self, raw):
        """Returns a summary, needed for 'short.html' template.

        :returns """

        taxonomies = []
        namespace = "haveibeenpwned"
        predicate = "email"

        count = len(raw['breaches'])
        if count == 0:
            level = 'info'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, "No breaches found"))
        elif count <= 3:
            level = 'suspicous'
        else:
            level = 'malicous'

        for breach in raw['breaches']:
            value = "The <{}> breach ({}) exposed {}".format(breach['Name'], breach['BreachDate'], list_to_print_string(breach['DataClasses']))
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {'taxonomies': taxonomies}

    def run(self):
        self.email = self.getData()
        self.results = check_email(self.email)
        if 'error' in self.results:
            self.error(self.results['error'])
        self.report(self.results)

if __name__ == '__main__':
    haveibeenpwnedAnalyzer().run()
