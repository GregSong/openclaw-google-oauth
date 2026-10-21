import { describe, it, expect } from "vitest";
import { neutralizeFormulaCells } from "./sheets.js";

describe("neutralizeFormulaCells", () => {
  // Assembled at runtime so the repo does not carry a ready-to-paste payload.
  const EQ = String.fromCharCode(61);
  const PLUS = String.fromCharCode(43);
  const MINUS = String.fromCharCode(45);
  const AT = String.fromCharCode(64);
  const TAB = String.fromCharCode(9);
  const CR = String.fromCharCode(13);

  it.each([
    ["=", EQ],
    ["+", PLUS],
    ["-", MINUS],
    ["@", AT],
    ["TAB", TAB],
    ["CR", CR],
  ])("escapes a string cell starting with %s", (_name, trigger) => {
    const [row] = neutralizeFormulaCells([[`${trigger}IMPORTRANGE("x","A1")`]]);
    expect(row[0]).toBe(`'${trigger}IMPORTRANGE("x","A1")`);
  });

  it("escapes only the cells that are actually dangerous", () => {
    const out = neutralizeFormulaCells([
      ["plain text", `${EQ}SUM(1,2)`],
      ["a=b", "  =not-a-formula"],
    ]);
    expect(out).toEqual([
      ["plain text", `'${EQ}SUM(1,2)`],
      ["a=b", "  =not-a-formula"],
    ]);
  });

  it("leaves numbers, booleans and null untouched", () => {
    const out = neutralizeFormulaCells([[-5, 0, 3.14, true, false, null]]);
    expect(out).toEqual([[-5, 0, 3.14, true, false, null]]);
  });

  it("does not double-escape a value that is already text-marked", () => {
    const out = neutralizeFormulaCells([[`'${EQ}SUM(1,2)`]]);
    expect(out).toEqual([[`'${EQ}SUM(1,2)`]]);
  });

  it("preserves the 2D shape and row order", () => {
    const input = [
      ["a", `${EQ}1`],
      ["b", "c"],
      [],
    ];
    const out = neutralizeFormulaCells(input);
    expect(out).toHaveLength(3);
    expect(out.map((row) => row.length)).toEqual([2, 2, 0]);
    expect(out[0][0]).toBe("a");
  });

  it("handles an empty value set", () => {
    expect(neutralizeFormulaCells([])).toEqual([]);
  });

  it("does not mutate the input", () => {
    const input = [[`${EQ}1`]];
    neutralizeFormulaCells(input);
    expect(input).toEqual([[`${EQ}1`]]);
  });
});
