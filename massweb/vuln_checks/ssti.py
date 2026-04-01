""" Server-Side Template Injection (SSTI) Checker """

from massweb.vuln_checks.match import match_strings
from massweb.vuln_checks.check import Check


class SSTICheck(Check):
    """ Server-Side Template Injection Checker: Checks for evidence of
        successful SSTI in result from fuzzers.

        SSTI occurs when user input is embedded directly in a server-side
        template without sanitization, allowing an attacker to inject template
        directives. Depending on the template engine, this can lead to
        information disclosure or remote code execution. Detection here looks
        for well-known template engine error messages returned in the response.
    """

    def __init__(self):
        """ Initialize the object and normalize the strings used to check for
            vulnerability in the response. """
        vuln_strings_raw = [
            # Jinja2 / Flask (Python)
            "jinja2.exceptions.templatesyntaxerror",
            "jinja2.exceptions.undefinederror",
            "jinja2.exceptions.templatenotfound",
            "jinja2.undefined",
            # Django template engine
            "django.template.exceptions.templatesyntaxerror",
            "templaterespondermixin",
            # Mako (Python)
            "mako.exceptions.syntaxexception",
            "mako.template",
            # Tornado template
            "tornado.template.parseerror",
            # Twig (PHP)
            "twig_error_syntax",
            "twig\\error\\syntax",
            "twig/twig",
            "twig error",
            # Smarty (PHP)
            "smarty_compilerexception",
            "smarty error:",
            # Blade (Laravel/PHP)
            "illuminate\\view\\compilers",
            # Freemarker (Java)
            "freemarker.template.",
            "freemarker template error",
            "freemarker.core.",
            # Velocity (Java)
            "org.apache.velocity",
            "velocityexception",
            # Pebble (Java)
            "pebble.template",
            "pebbleexception",
            # Thymeleaf (Java)
            "org.thymeleaf",
            "thymeleafexception",
            # ERB / ActionView (Ruby)
            "actionview::template::error",
            "erb parse error",
            # Mustache
            "mustache.js",
            "hogan.js",
            # Handlebars
            "handlebars.exception",
            # Golang templates
            "executing template",
        ]
        self.vuln_strings = [x.lower() for x in vuln_strings_raw]

    def check(self, content):
        """ Check the string returned by the fuzzer (content) against the list
            of strings indicating vulnerability. """
        content = content.lower()
        return match_strings(content, self.vuln_strings)
