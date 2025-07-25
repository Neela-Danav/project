(function () {
  const results = [];

  document.querySelectorAll('[id^="finding-card"]').forEach((card) => {
    const titleEl = card.querySelector("#finding-title");
    const title = titleEl ? titleEl.textContent.trim() : "Untitled";

    const monacoEditor = card.querySelector(".monaco-editor");
    if (!monacoEditor) return;

    const lines = [];

    // Loop through each Monaco line
    monacoEditor.querySelectorAll(".view-line").forEach((line) => {
      const spans = Array.from(line.querySelectorAll("span"));
      const containsHighlight = spans.some((span) =>
        span.className.includes("highlight"),
      );
      if (!containsHighlight) return;

      // Collect plain text from all spans (preserves indentation!)
      const lineText = spans.map((span) => span.textContent).join("");
      lines.push(lineText.trimEnd());
    });

    if (lines.length > 0) {
      results.push({ title, code: lines });
    }
  });

  // Output
  if (results.length === 0) {
    console.log("No highlighted Monaco code found.");
  } else {
    console.log("========== HIGHLIGHTED MONACO CODE ==========");
    results.forEach((entry, i) => {
      console.log(`\n${i + 1}. ${entry.title}\n`);
      entry.code.forEach((line) => console.log(line));
    });
    console.log("==============================================");
  }

  return results;
})();
