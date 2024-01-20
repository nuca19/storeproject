document.getElementById('cardNumber').addEventListener('input', function (e) {
  e.target.value = e.target.value.replace(/[^\dA-Z]/g, '').replace(/(.{4})/g, '$1 ').trim();
});

document.getElementById('cardCCV').addEventListener('keypress', function (e) {
  if (e.key < '0' || e.key > '9') {
      e.preventDefault();
  }
});

document.getElementById('cardExp').addEventListener('input', function (e) {
  e.target.value = e.target.value.replace(/(\d{2})(\d{2})/, "$1/$2").substr(0, 5);
  var match = e.target.value.match(/(\d{2})\/(\d{2})/);
  if (match) {
      var month = parseInt(match[1], 10);
      var year = parseInt(match[2], 10);
      var currentYear = new Date().getFullYear() % 100;
      var currentMonth = new Date().getMonth() + 1;

      // Check if the month is between 1 and 12, and the year is not in the past
      if (month < 1 || month > 12 || year < currentYear || (year === currentYear && month < currentMonth)) {
          e.target.setCustomValidity("Invalid date");
      } else {
          e.target.setCustomValidity("");
      }
  }
});



function enableDETI_pickup() {
    if (document.getElementById("DETI_pickup").checked) {
      disableForm(true);
    }
    if (!document.getElementById("DETI_pickup").checked) {
      disableForm(false);
    }
  
}
  
function disableForm(flag) {
    var elements = document.getElementsByClassName("form-control");
    for (var i = 0, len = elements.length; i < len; ++i) {
      elements[i].readOnly = flag;
      elements[i].disabled = flag;
    }
}


