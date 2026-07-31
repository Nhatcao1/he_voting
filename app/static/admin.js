function number(value) {
  return new Intl.NumberFormat().format(value);
}

function bytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

async function refresh() {
  const response = await fetch("/demo/progress");
  if (!response.ok) throw new Error("Could not load election progress.");
  const data = await response.json();
  document.querySelector("#participants").textContent =
    `${number(data.participating_employees)} / ${number(data.eligible_employees)}`;
  document.querySelector("#ballots").textContent =
    number(data.encrypted_ballots);
  document.querySelector("#files").textContent =
    number(data.ciphertext_files);
  document.querySelector("#storage").textContent =
    bytes(data.ciphertext_storage_bytes);
  document.querySelector("#context-id").textContent = data.context_id;
  document.querySelector("#latest").textContent = data.latest_submission
    ? new Date(data.latest_submission).toLocaleString()
    : "No submissions yet";
  document.querySelector("#result-state").textContent =
    data.result_published ? "Published" : "Encrypted only";
}

refresh().catch(console.error);
setInterval(() => refresh().catch(console.error), 3000);
