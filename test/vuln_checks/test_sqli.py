
import unittest
from util import expand_cases 
from massweb.vuln_checks import sqli

class TestSQLICheck(unittest.TestCase):

    def setUp(self):
        true = ["you have an error in your sql syntax",
                "supplied argument is not a valid mysql",
                "[microsoft][odbc microsoft acess driver]",
                "[microsoft][odbc sql server driver]",
                "microsoft ole db provider for odbc drivers",
                "java.sql.sqlexception: syntax error or access violation",
                "postgresql query failed: error: parser:",
                "db2 sql error:",
                "dynamic sql error",
                "sybase message:",
                "ora-01756: quoted string not properly terminated",
                "ora-00933: sql command not properly ended",
                "pls-00306: wrong number or types",
                "incorrect syntax near",
                "unclosed quotation mark before",
                "syntax error containing the varchar value",
                "ora-01722: invalid number",
                "ora-01858: a non-numeric character was found where a numeric was expected",
                "ora-00920: invalid relational operator",
                "ora-00920: missing right parenthesis",
                # Modern MySQL/MariaDB
                "mysql_fetch_array() expects parameter 1 to be resource",
                "mysqli_fetch_array() expects parameter 1 to be mysqli_result",
                "warning: mysql_",
                "function.mysql",
                # Modern PostgreSQL
                "pg_query(): query failed:",
                "error: unterminated quoted string at or near",
                "error: syntax error at end of input",
                # SQLite
                "sqlite_excl",
                "sqlite error",
                "sqlite3::query:",
                # MSSQL modern
                "must declare the scalar variable",
                "conversion failed when converting",
                "operand type clash",
                # Generic ORM errors
                "activerecord::statementinvalid",
                "pdo::query()",
                "pdo::exec()",
                "pdostatement::execute()",
                "django.db.utils.operationalerror",
                "django.db.utils.programmingerror"]
        self.true = expand_cases([x.lower() for x in true])
        self.false = ['', "mary had a little lamb", "i want to be an edge case"]

    def test_sqli_check(self):
        s = sqli.SQLICheck()
        for t in self.true:
            self.assertTrue(s.check(t))
        for f in self.false:
            self.assertFalse(s.check(f))



if __name__ == "__main__":
    unittest.main()

