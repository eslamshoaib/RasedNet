import { tableFeatures, useTable, type ColumnDef, type RowData } from "@tanstack/react-table";
import { t } from "../i18n";
import { Empty } from "./ui";

// Rows are paginated, sorted and filtered on the server; the table only renders them.
export const features = tableFeatures({});
export type Features = typeof features;
export type Columns<T extends RowData> = ColumnDef<Features, T, any>[];

interface Props<T extends RowData> {
  data: T[];
  columns: Columns<T>;
  rowKey: (row: T) => string | number;
  onRowClick?: (row: T) => void;
  empty?: string;
}

export function DataTable<T extends RowData>({ data, columns, rowKey, onRowClick, empty = t("لا توجد بيانات", "No data") }: Props<T>) {
  const table = useTable({ features, columns, data, getRowId: (row: T) => String(rowKey(row)) });
  if (data.length === 0) return <Empty>{empty}</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          {table.getHeaderGroups().map((group) => (
            <tr key={group.id} className="border-b border-slate-200 bg-slate-50">
              {group.headers.map((header) => (
                <th key={header.id} scope="col" className="whitespace-nowrap px-3 py-2 text-start font-semibold text-slate-600">
                  {header.isPlaceholder ? null : <table.FlexRender header={header} />}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr
              key={row.id}
              onClick={onRowClick ? () => onRowClick(row.original) : undefined}
              className={`border-b border-slate-100 ${onRowClick ? "cursor-pointer hover:bg-cyan-50" : ""}`}
            >
              {row.getAllCells().map((cell) => (
                <td key={cell.id} className="px-3 py-2 align-top text-slate-700">
                  <table.FlexRender cell={cell} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
