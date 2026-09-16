(() => {
  const nav = document.querySelector(".primary-nav");
  const toggle = nav?.querySelector(".nav-toggle");
  const links = nav?.querySelectorAll(".nav-list a");

  const setNavOpen = open => {
    if (!nav || !toggle) return;
    nav.classList.toggle("is-open", open);
    toggle.setAttribute("aria-expanded", String(open));
  };

  toggle?.addEventListener("click", () => {
    setNavOpen(!nav.classList.contains("is-open"));
  });

  links?.forEach(link => link.addEventListener("click", () => setNavOpen(false)));

  document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
      setNavOpen(false);
      toggle?.focus();
    }
  });

  const toc = document.querySelector("[data-toc]");
  const postContent = document.querySelector(".post-content");

  if (toc && postContent) {
    const articleTitle = postContent.querySelector("h1");
    const headings = [...postContent.querySelectorAll("h1, h2, h3")]
      .filter(heading => heading !== articleTitle);

    if (headings.length < 2) {
      toc.closest(".toc-panel")?.setAttribute("hidden", "");
    } else {
      const list = document.createElement("ol");
      const usedIds = new Set();

      headings.forEach((heading, index) => {
        let id = heading.id || heading.textContent
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9\s-]/g, "")
          .replace(/\s+/g, "-")
          .replace(/-+/g, "-");

        id = id || `section-${index + 1}`;
        const baseId = id;
        let suffix = 2;

        while (usedIds.has(id) || (document.getElementById(id) && document.getElementById(id) !== heading)) {
          id = `${baseId}-${suffix}`;
          suffix += 1;
        }

        usedIds.add(id);
        heading.id = id;

        const item = document.createElement("li");
        const level = heading.tagName === "H3" ? "h3" : "h2";
        item.className = `toc-level-${level}`;

        const link = document.createElement("a");
        link.href = `#${id}`;
        link.textContent = heading.textContent;

        item.append(link);
        list.append(item);
      });

      toc.append(list);
    }
  }

  const progress = document.querySelector("[data-reading-progress]");
  const article = document.querySelector(".post-content");

  if (progress && article) {
    let ticking = false;

    const updateProgress = () => {
      const articleTop = article.getBoundingClientRect().top + window.scrollY;
      const distance = article.offsetHeight - window.innerHeight;
      const amount = distance > 0 ? (window.scrollY - articleTop) / distance : 1;
      const clamped = Math.min(Math.max(amount, 0), 1);
      progress.style.transform = `scaleX(${clamped})`;
      ticking = false;
    };

    window.addEventListener("scroll", () => {
      if (!ticking) {
        window.requestAnimationFrame(updateProgress);
        ticking = true;
      }
    }, { passive: true });

    updateProgress();
  }

  document.querySelectorAll(".post-content img").forEach((image, index) => {
    if (index > 0 && !image.hasAttribute("loading")) {
      image.loading = "lazy";
    }
    image.decoding = "async";
  });
})();
