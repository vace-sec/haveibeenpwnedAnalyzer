#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import requests

HEADERS = {'User-Agent': 'github.com/vace-sec/haveibeenpwnedAnalyzer v1.0', 'api-version': '2'}
email_url = 'https://haveibeenpwned.com/api/v2/breachedaccount/{}'
params = {'includeUnverified': 'true'}
error_messages = {
    400: "Bad request — the account does not comply with an acceptable format "
         "(i.e. it's an empty string)",
    403: "Forbidden — no user agent has been specified in the request",
    429: "Too many requests — the rate limit has been exceeded",
    526: "Cloudflare SSL Error - please try again later"
}

def list_to_print_string(l):
    if len(l) == 1:
        return l[0]
    else:
        return ", ".join(l[:-1]) + " and {}".format(l[-1])

def check_email(email):
    response = requests.get(email_url.format(email), headers=HEADERS, params=params)
    http_status = response.status_code
    if http_status == 403:
        response = requests.get(email_url.format(email), headers=HEADERS)  # try again without includeUnverified
        http_status = response.status_code
    if http_status == 200:
        return {
            'breaches': response.json()
        }
    elif http_status == 404:
        return {'breaches': []}
    else:
        message = error_messages.get(http_status, "Unknown error: {}".format(http_status))
        return {
            'error': message,
            'breaches': ''
        }

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
        elif count == 1:
            level = 'suspicious'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, "1 breache"))
        elif count <= 3:
            level = 'suspicious'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, str(count) + " breaches"))
        else:
            level = 'malicious'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, str(count) + " breaches"))


        return {'taxonomies': taxonomies}

    def run(self):
        self.email = self.getData()
        self.results = check_email(self.email)
        if 'error' in self.results:
            self.error(self.results['error'])
        self.report(self.results)

if __name__ == '__main__':
    haveibeenpwnedAnalyzer().run()
