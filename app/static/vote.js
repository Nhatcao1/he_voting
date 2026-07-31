const employeeSelect = document.querySelector("#employee-id");
const form = document.querySelector("#vote-form");
const submitButton = document.querySelector("#submit-vote");
const statusBox = document.querySelector("#status");

async function loadEmployees() {
  const response = await fetch("/demo/employees");
  if (!response.ok) throw new Error("Could not load prepared employees.");
  const employees = await response.json();
  employeeSelect.innerHTML = '<option value="">Select an employee</option>';
  for (const employee of employees) {
    const option = document.createElement("option");
    option.value = employee.employee_id;
    option.textContent = `${employee.employee_id} — ${employee.display_name}`;
    employeeSelect.appendChild(option);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  statusBox.className = "status hidden";
  submitButton.disabled = true;
  submitButton.textContent = "Encrypting and adding…";
  const choice = new FormData(form).get("choice");
  try {
    const response = await fetch("/demo/vote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        employee_id: employeeSelect.value,
        choice,
      }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Submission failed.");
    statusBox.className = "status";
    statusBox.textContent =
      `Accepted as encrypted ballot #${body.sequence}. ` +
      `Receipt ${body.receipt.slice(0, 16)}…`;
  } catch (error) {
    statusBox.className = "status error";
    statusBox.textContent = error.message;
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Encrypt and submit";
  }
});

loadEmployees().catch((error) => {
  statusBox.className = "status error";
  statusBox.textContent = error.message;
});
