async function loadResult() {
  const state = document.querySelector("#result-state");
  const response = await fetch("/election/result");
  if (response.status === 404) {
    state.textContent =
      "The A/B/C totals are still encrypted. Run trustee decryption and publish the result when the election is ready.";
    return;
  }
  if (!response.ok) throw new Error("Could not load the published result.");
  const result = await response.json();
  for (const choice of ["A", "B", "C"]) {
    document.querySelector(`#result-${choice.toLowerCase()}`).textContent =
      result[choice];
  }
  document.querySelector("#published-results").classList.remove("hidden");
  state.textContent = "Trustee result published.";
}

loadResult().catch((error) => {
  document.querySelector("#result-state").textContent = error.message;
});
