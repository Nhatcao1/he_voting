let currentPage = 1;
const pageSize = 50;

function number(value) {
  return new Intl.NumberFormat().format(value);
}

function bytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(1)} GiB`;
}

function code(value, title) {
  const element = document.createElement("code");
  element.textContent = value;
  element.title = title || value;
  return element;
}

async function loadStorage(page) {
  const response = await fetch(
    `/demo/storage?page=${page}&page_size=${pageSize}`,
  );
  if (!response.ok) throw new Error("Could not load ciphertext storage.");
  const data = await response.json();
  currentPage = data.pagination.page;

  document.querySelector("#retained-ballots").textContent =
    number(data.summary.retained_ballots);
  document.querySelector("#total-files").textContent =
    number(data.summary.total_files);
  document.querySelector("#total-storage").textContent =
    bytes(data.summary.total_bytes);
  document.querySelector("#storage-context").textContent = data.context_id;

  const body = document.querySelector("#storage-rows");
  body.replaceChildren();
  if (data.files.length === 0) {
    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 5;
    cell.textContent = "No ciphertext files found.";
  }
  for (const file of data.files) {
    const row = body.insertRow();
    row.insertCell().textContent = file.category;
    const pathCell = row.insertCell();
    pathCell.className = "file-path";
    pathCell.textContent = file.path;
    row.insertCell().textContent = bytes(file.bytes);
    row.insertCell().appendChild(code(file.sha256));
    row.insertCell().appendChild(
      code(file.preview_base64, "First 48 encrypted bytes as Base64"),
    );
  }

  document.querySelector("#page-state").textContent =
    `Page ${data.pagination.page} of ${data.pagination.total_pages}`;
  document.querySelector("#previous-page").disabled =
    data.pagination.page <= 1;
  document.querySelector("#next-page").disabled =
    data.pagination.page >= data.pagination.total_pages;
}

document.querySelector("#previous-page").addEventListener("click", () => {
  loadStorage(currentPage - 1).catch(showError);
});

document.querySelector("#next-page").addEventListener("click", () => {
  loadStorage(currentPage + 1).catch(showError);
});

function showError(error) {
  const status = document.querySelector("#storage-status");
  status.className = "status error";
  status.textContent = error.message;
}

loadStorage(currentPage).catch(showError);
