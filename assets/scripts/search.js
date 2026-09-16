(() => {
  const script = document.currentScript;
  const form = document.querySelector("[data-search-form]");
  const input = document.querySelector("[data-search-input]");
  const status = document.querySelector("[data-search-status]");
  const results = document.querySelector("[data-search-results]");

  if (!script || !form || !input || !status || !results) return;

  const normalize = value => String(value || "").toLocaleLowerCase();
  let pages = [];

  const render = matches => {
    results.replaceChildren();

    matches.forEach(page => {
      const item = document.createElement("li");
      item.className = "search-result";

      const article = document.createElement("article");
      const heading = document.createElement("h2");
      const link = document.createElement("a");
      const summary = document.createElement("p");

      link.href = page.url;
      link.textContent = page.title;
      summary.textContent = String(page.excerpt || page.content || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 220);

      heading.append(link);
      article.append(heading, summary);
      item.append(article);
      results.append(item);
    });
  };

  const search = () => {
    const query = normalize(input.value).trim();

    if (query.length < 2) {
      results.replaceChildren();
      status.textContent = "Enter at least two characters to search.";
      return;
    }

    const matches = pages
      .filter(page => normalize(`${page.title} ${page.content}`).includes(query))
      .slice(0, 20);

    render(matches);
    status.textContent = matches.length
      ? `${matches.length} result${matches.length === 1 ? "" : "s"} found.`
      : "No matching articles found.";
  };

  form.addEventListener("submit", event => event.preventDefault());
  input.addEventListener("input", search);

  fetch(script.dataset.searchEndpoint)
    .then(response => {
      if (!response.ok) throw new Error(`Search index request failed with ${response.status}`);
      return response.json();
    })
    .then(data => {
      pages = data;
      if (input.value) search();
    })
    .catch(error => {
      status.textContent = "Search is temporarily unavailable.";
      console.error(error);
    });
})();
