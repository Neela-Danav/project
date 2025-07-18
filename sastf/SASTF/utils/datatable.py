__doc__ = """
This module covers a class to support JQuery DataTable within the REST
API of this project. It is recommended to use ``apply(...)`` to filter
a specific queryset.

.. important::
    All list views of the REST API support jQuery DataTable requests, so
    sorting, filtering and search will be applied to all of them.

"""
import logging

from django.http.request import HttpRequest
from django.db.models import QuerySet, Q

logger = logging.getLogger(__name__)


class DataTableRequest:

    def __init__(self, request: HttpRequest) -> None:
        self.request = request
        self._columns = []
        self._parse()

    @property
    def start(self) -> int:
        """Defines the starting pointer.

        :return: an integer pointing to the starting offset position
        :rtype: int
        """
        return int(self.request.GET.get("start", 0))

    @property
    def length(self) -> int:
        """Defines the preferred return size.

        :return: an integer or ``0`` if this parameter is not present.
        :rtype: int
        """
        return int(self.request.GET.get("length", 0))

    @property
    def columns(self) -> list:
        """Specifies all column data that is present within this request.

        :return: a list of column structures.
        :rtype: list
        """
        return self._columns

    @property
    def search_value(self) -> str:
        """Defines a global search value

        :return: _description_
        :rtype: str
        """
        return self.request.GET.get("search[value]", "")

    @property
    def order_column(self) -> int:
        """The column index which points to a column that should be ordered.

        :return: ``-1`` if no column is selected ot the column index
        :rtype: int
        """
        return int(self.request.GET.get("order[0][column]", "-1"))

    @property
    def order_direction(self) -> str:
        """Specifies the order direction.

        :return: the direction as string (either ``asc`` or ``desc``)
        :rtype: str
        """
        return self.request.GET.get("order[0][dir]", "desc")

    def _parse(self):
        index = 0
        while True:
            column = self.request.GET.get(f"columns[{index}][data]", None)
            if not column:
                break

            query_params = {}
            if self.request.GET.get(f"columns[{index}][searchable]", True):
                value = (
                    self.request.GET.get(f"columns[{index}][search][value]", "")
                    or self.search_value
                )
                if value:
                    query_params[f"{column}__icontains"] = value

            self._columns.append({"params": query_params, "name": column})
            index += 1


def apply(request: DataTableRequest, queryset: QuerySet) -> QuerySet:
    """Utility function that applies filters or ordering to a Django queryset"""
    model = queryset.model
    query: Q = None
    for column in request.columns:
        if not hasattr(model, column["name"]):
            logger.debug(f'Skipped column definition: {column["name"]}')
            continue

        next_query = Q(**column["params"])
        if not query:
            query = next_query
        else:
            query = next_query | query

    queryset = queryset.filter(query) if query else queryset
    order_column = request.order_column
    if order_column != -1:
        order_column = request.columns[order_column]["name"]
        if not hasattr(queryset.model, order_column):
            logger.debug(
                f"Switching non-existend order-column '{order_column}' to 'pk'"
            )
            order_column = "pk"

        if str(request.order_direction).lower() == "desc":
            order_column = f"-{order_column}"

        queryset = queryset.order_by(order_column)
    else:
        queryset = queryset.order_by("pk")

    return queryset
