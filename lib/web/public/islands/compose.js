// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Compose conveniences: grow the message box as it fills, and ask before
// leaving a draft that has been typed into and not sent. The form works
// without this file; what it loses is the warning and the resizing.
//
// There is deliberately no address check here. The server decides which
// addresses it will accept, and a second opinion in the browser is a
// second answer waiting to disagree with the first.

(function () {
  var form = document.querySelector('form[data-island="compose"]');
  if (!form) return;

  // The three fields are joined on U+0000 to decide whether anything was
  // typed. That separator is the right one because a form control cannot
  // contain it, so no combination of field values can imitate a
  // different combination and read as unchanged.
  //
  // It is built rather than written as a literal on purpose. A source
  // file carrying a raw NUL is classified as binary, which drops it out
  // of line-ending normalization and out of every diff a reviewer reads,
  // so the file this rule protects becomes the file nobody can review.
  // Keeping the source printable costs one call at startup.
  var SEP = String.fromCharCode(0);

  var text = form.querySelector("textarea");
  var startedWith = form.querySelector("#to").value + SEP +
    form.querySelector("#subject").value + SEP +
    (text ? text.value : "");
  var sending = false;

  // ---- Grow the message box ---------------------------------------

  if (text) {
    var grow = function () {
      text.style.height = "auto";
      var wanted = text.scrollHeight;
      var ceiling = Math.round(window.innerHeight * 0.7);
      text.style.height = (wanted > ceiling ? ceiling : wanted) + "px";
    };
    text.addEventListener("input", grow);
    grow();
  }

  // ---- Ask before losing a draft ----------------------------------

  form.addEventListener("submit", function () { sending = true; });

  window.addEventListener("beforeunload", function (event) {
    if (sending) return;
    var now = form.querySelector("#to").value + SEP +
      form.querySelector("#subject").value + SEP +
      (text ? text.value : "");
    if (now === startedWith) return;
    event.preventDefault();
    // Browsers show their own wording; the returned value only signals
    // that the page has something worth keeping.
    event.returnValue = "";
  });
}());
