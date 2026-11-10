(() => {
  const catalog = window.ARCHIVE_CATALOG;
  const bookSelect = document.querySelector("#bookSelect");
  const filterInput = document.querySelector("#filterInput");
  const lessonList = document.querySelector("#lessonList");
  const lessonCount = document.querySelector("#lessonCount");
  const activeTitle = document.querySelector("#activeTitle");
  const activeMeta = document.querySelector("#activeMeta");
  const contentFrame = document.querySelector("#contentFrame");

  let activeBook = catalog.books[0];
  let activeIndex = 0;

  const params = new URLSearchParams(location.search);
  const requestedBook = catalog.books.find(book => book.id === params.get("book"));
  if (requestedBook) activeBook = requestedBook;
  const requestedIndex = Number.parseInt(params.get("lesson") || "0", 10);
  if (Number.isInteger(requestedIndex) && requestedIndex >= 0 && requestedIndex < activeBook.lessons.length) {
    activeIndex = requestedIndex;
  }

  for (const book of catalog.books) {
    const option = document.createElement("option");
    option.value = book.id;
    option.textContent = book.title;
    bookSelect.append(option);
  }
  bookSelect.value = activeBook.id;

  function selectLesson(index) {
    const lesson = activeBook.lessons[index];
    if (!lesson) return;
    activeIndex = index;
    activeTitle.textContent = lesson.title;
    activeMeta.textContent = [lesson.lessonNum, lesson.phase, lesson.modules].filter(Boolean).join(" · ");
    contentFrame.src = `lessons/${activeBook.id}/${String(index + 1).padStart(3, "0")}.html`;
    renderLessons();
  }

  function renderLessons() {
    const term = filterInput.value.trim().toLocaleLowerCase();
    lessonCount.textContent = `${activeBook.lessons.length} lessons`;
    lessonList.replaceChildren();
    let previousPhase = "";
    let shown = 0;

    activeBook.lessons.forEach((lesson, index) => {
      const searchText = `${lesson.title} ${lesson.phase} ${lesson.modules} ${lesson.lessonNum}`.toLocaleLowerCase();
      if (term && !searchText.includes(term)) return;
      if (lesson.phase && lesson.phase !== previousPhase) {
        const heading = document.createElement("h3");
        heading.className = "phase-title";
        heading.textContent = lesson.phase;
        lessonList.append(heading);
        previousPhase = lesson.phase;
      }
      const button = document.createElement("button");
      button.type = "button";
      button.className = "lesson-link";
      button.textContent = `${lesson.lessonNum}. ${lesson.title}`;
      if (index === activeIndex) button.setAttribute("aria-current", "page");
      button.addEventListener("click", () => selectLesson(index));
      lessonList.append(button);
      shown++;
    });

    if (!shown) {
      const empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "No matching lessons.";
      lessonList.append(empty);
    }
  }

  bookSelect.addEventListener("change", () => {
    activeBook = catalog.books.find(book => book.id === bookSelect.value) || catalog.books[0];
    activeIndex = 0;
    filterInput.value = "";
    selectLesson(activeIndex);
  });
  filterInput.addEventListener("input", renderLessons);
  selectLesson(activeIndex);
})();
