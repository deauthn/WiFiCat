"""Pretty-print tabular data with enhanced structure and functions."""

from __future__ import (
    print_function,
    unicode_literals,
)

from collections import namedtuple

Line = namedtuple(
    "Line", ["begin", "hline", "sep", "end"]
)
DataRow = namedtuple(
    "DataRow", ["begin", "sep", "end"]
)
TableFormat = namedtuple(
    "TableFormat",
    [
        "lineabove",
        "linebelowheader",
        "linebetweenrows",
        "linebelow",
        "headerrow",
        "datarow",
        "padding",
        "with_header_hide",
    ],
)

MIN_PADDING = 2
DEFAULT_FLOATFMT = "g"
DEFAULT_MISSINGVAL = ""
WIDE_CHARS_MODE = False


class Tabulate:
    def __init__(
        self,
        tabular_data,
        headers=None,
        tablefmt="simple",
        floatfmt=DEFAULT_FLOATFMT,
        numalign="decimal",
        stralign="left",
        missingval=DEFAULT_MISSINGVAL,
        showindex="default",
    ):
        self.tabular_data = tabular_data
        self.headers = headers
        self.tablefmt = tablefmt
        self.floatfmt = floatfmt
        self.numalign = numalign
        self.stralign = stralign
        self.missingval = missingval
        self.showindex = showindex

    @property
    def formatted_table(self):
        list_of_lists, headers = (
            self._normalize_tabular_data()
        )
        return self._format_table(
            headers, list_of_lists
        )

    def _normalize_tabular_data(self):
        headers = self.headers or []
        rows = self.tabular_data

        if headers == "firstrow" and rows:
            headers = rows[0]
            rows = rows[1:]

        return rows, headers

    def _format_table(self, headers, rows):
        output = []
        if headers:
            output.append(
                " | ".join(headers)
            )
            output.append(
                "-"
                * (len(" | ".join(headers)))
            )

        for row in rows:
            output.append(
                " | ".join(
                    str(item)
                    if item is not None
                    else self.missingval
                    for item in row
                )
            )

        return "\n".join(output)


def tabulate(
    tabular_data,
    headers=(),
    tablefmt="simple",
    floatfmt=DEFAULT_FLOATFMT,
    numalign="decimal",
    stralign="left",
    missingval=DEFAULT_MISSINGVAL,
    showindex="default",
):
    table = Tabulate(
        tabular_data,
        headers,
        tablefmt,
        floatfmt,
        numalign,
        stralign,
        missingval,
        showindex,
    )
    return table.formatted_table


if __name__ == "__main__":
    data = [["Alice", 24], ["Bob", 19]]
    headers = ["Name", "Age"]
    print(tabulate(data, headers=headers))
