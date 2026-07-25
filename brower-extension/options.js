const apiKeyEl = document.getElementById("apiKey");
const brandsEl = document.getElementById("brands");
const savedEl = document.getElementById("saved");

chrome.storage.sync.get(["apiKey", "customBrands"], (data) => {
  if (data.apiKey) apiKeyEl.value = data.apiKey;
  if (data.customBrands) brandsEl.value = JSON.stringify(data.customBrands, null, 2);
});

document.getElementById("save").addEventListener("click", () => {
  let customBrands = {};
  const raw = brandsEl.value.trim();
  if (raw) {
    try {
      customBrands = JSON.parse(raw);
    } catch (e) {
      alert("Custom brands JSON is invalid: " + e.message);
      return;
    }
  }
  chrome.storage.sync.set({ apiKey: apiKeyEl.value.trim(), customBrands }, () => {
    savedEl.textContent = "Saved!";
    setTimeout(() => (savedEl.textContent = ""), 1500);
  });
});