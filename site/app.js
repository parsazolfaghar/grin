// GRIN site — vanilla, perf-safe. Scroll reveals (IntersectionObserver), copy-one-liner, mobile nav.
(() => {
  "use strict";

  // ── staggered scroll reveals ──────────────────────────────────────────────
  const reveals = document.querySelectorAll(".reveal");
  const showAll = () => reveals.forEach((el) => el.classList.add("in"));
  try {
    if ("IntersectionObserver" in window && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      const io = new IntersectionObserver((entries) => {
        entries.forEach((e, i) => {
          if (!e.isIntersecting) return;
          e.target.style.transitionDelay = Math.min(i * 70, 280) + "ms";
          e.target.classList.add("in");
          io.unobserve(e.target);
        });
      }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
      reveals.forEach((el) => io.observe(el));
      // Safety net: nothing may stay hidden. If an element is still unrevealed after 4s
      // (slow IO, edge cases, capture tools), force it visible. Content > animation.
      setTimeout(showAll, 4000);
    } else {
      showAll();
    }
  } catch {
    showAll();
  }

  // ── copy install one-liner ────────────────────────────────────────────────
  document.querySelectorAll(".cmd-copy").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const node = document.querySelector(btn.dataset.copy);
      if (!node) return;
      const text = node.textContent.trim();
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        const r = document.createRange(); r.selectNode(node);
        const s = getSelection(); s.removeAllRanges(); s.addRange(r);
        try { document.execCommand("copy"); } catch {}
        s.removeAllRanges();
      }
      const old = btn.textContent;
      btn.textContent = "COPIED"; btn.classList.add("done");
      setTimeout(() => { btn.textContent = old; btn.classList.remove("done"); }, 1600);
    });
  });

  // ── mobile nav ────────────────────────────────────────────────────────────
  const burger = document.querySelector(".nav-burger");
  const modal = document.querySelector(".navmodal");
  if (burger && modal) {
    const close = () => { modal.hidden = true; burger.setAttribute("aria-expanded", "false"); document.body.style.overflow = ""; };
    burger.addEventListener("click", () => {
      const open = burger.getAttribute("aria-expanded") === "true";
      if (open) return close();
      modal.hidden = false; burger.setAttribute("aria-expanded", "true"); document.body.style.overflow = "hidden";
    });
    modal.querySelectorAll("a").forEach((a) => a.addEventListener("click", close));
    addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  }
})();
