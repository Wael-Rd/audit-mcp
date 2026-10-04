(() => {
  "use strict";
  const rows = [...document.querySelectorAll(".check-row")];
  const buttons = [...document.querySelectorAll("[data-filter]")];
  const search = document.getElementById("search");
  const status = document.getElementById("filter-status");
  let filter = "all";
  function update() {
    const term = search.value.toLowerCase();
    let visible = 0;
    rows.forEach((row) => {
      row.hidden = !(
        (filter === "all" || row.dataset.status === filter) &&
        row.dataset.search.toLowerCase().includes(term)
      );
      if (!row.hidden) visible++;
    });
    buttons.forEach((button) =>
      button.classList.toggle("active", button.dataset.filter === filter),
    );
    status.textContent = `${visible} of ${rows.length} observed checks shown · independent reviews remain visible`;
  }
  buttons.forEach((button) =>
    button.addEventListener("click", () => {
      filter = button.dataset.filter;
      update();
    }),
  );
  search.addEventListener("input", update);
  document.getElementById("print-report").addEventListener("click", () => {
    filter = "all";
    search.value = "";
    update();
    window.print();
  });
  window.addEventListener("beforeprint", () =>
    rows.forEach((row) => {
      row.hidden = false;
    }),
  );
  const sections = [...document.querySelectorAll(".process-step")];
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          document
            .querySelectorAll(".rail nav a")
            .forEach((link) =>
              link.classList.toggle(
                "current",
                link.hash === `#${entry.target.id}`,
              ),
            );
          document.querySelector(".rail-label span").textContent =
            `${entry.target.id.replace("step-", "").padStart(2, "0")} / 10`;
        }
      });
    },
    { rootMargin: "-10% 0px -70% 0px" },
  );
  sections.forEach((section) => observer.observe(section));
  update();
})();
