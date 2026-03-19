import unittest
from massweb.vuln_checks import ssti


class TestSSTICheck(unittest.TestCase):

    def setUp(self):
        self.true = [
            # Jinja2 / Flask
            "jinja2.exceptions.TemplateNotFound",
            "jinja2.exceptions.TemplateSyntaxError",
            "jinja2.exceptions.UndefinedError",
            "jinja2.Undefined",
            # Django template
            "django.template.exceptions.TemplateSyntaxError",
            # Mako
            "mako.exceptions.SyntaxException",
            "mako.template",
            # Tornado
            "tornado.template.ParseError",
            # Twig (PHP)
            "Twig_Error_Syntax",
            "twig/twig",
            "Twig Error",
            # Smarty (PHP)
            "Smarty_CompilerException",
            "Smarty error:",
            # Blade / Laravel
            "Illuminate\\View\\Compilers",
            # Freemarker (Java)
            "freemarker.template.",
            "FreeMarker template error",
            "freemarker.core.",
            # Velocity (Java)
            "org.apache.velocity",
            "VelocityException",
            # Pebble (Java)
            "pebble.template",
            "PebbleException",
            # Thymeleaf (Java)
            "org.thymeleaf",
            "ThymeleafException",
            # ERB / ActionView (Ruby)
            "ActionView::Template::Error",
            "ERB parse error",
            # Handlebars
            "Handlebars.Exception",
        ]
        self.false = [
            '',
            "mary had a little lamb",
            "normal page content",
            "no template here",
            "jinja2 is a popular template engine for Python",
            "django tutorial: getting started with views",
            "freemarker documentation and examples",
            "template design patterns and best practices",
            "velocity of the project is increasing",
        ]

    def test_ssti_check(self):
        s = ssti.SSTICheck()
        for t in self.true:
            self.assertTrue(s.check(t), msg=f"Expected SSTI match for: {t!r}")
        for f in self.false:
            self.assertFalse(s.check(f), msg=f"Expected no SSTI match for: {f!r}")


if __name__ == "__main__":
    unittest.main()
