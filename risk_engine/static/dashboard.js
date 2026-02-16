// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {

const decisionCounts = {};
const reasonCounts = {};
const scores = [];

EVENTS.forEach(e => {
  decisionCounts[e.decision] = (decisionCounts[e.decision] || 0) + 1;
  scores.push(e.score);

  if (e.reasons) {
    JSON.parse(e.reasons).forEach(r => {
      reasonCounts[r] = (reasonCounts[r] || 0) + 1;
    });
  }
});

// Decision distribution
new Chart(document.getElementById("decisionChart"), {
  type: "pie",
  data: {
    labels: Object.keys(decisionCounts),
    datasets: [{ data: Object.values(decisionCounts) }]
  }
});

// Risk reason frequency
new Chart(document.getElementById("reasonChart"), {
  type: "bar",
  data: {
    labels: Object.keys(reasonCounts),
    datasets: [{ data: Object.values(reasonCounts) }]
  }
});

}); // End of DOMContentLoaded
