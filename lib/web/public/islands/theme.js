// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Theme switch. The buttons are an ordinary form post that works with
// scripting off: the server writes the preference cookie and sends the
// reader back to the page they were on. This upgrades that to an instant
// switch by painting the choice first and posting the cookie behind it.
//
// Nothing here builds markup, because the policy this page is served
// under requires a Trusted Types sink for anything that would. Reading
// and writing attributes needs no such thing.

(function () {
  var form = document.querySelector('form[data-island="theme"]');
  if (!form) return;

  function paint(choice) {
    var root = document.documentElement;
    if (choice === "light" || choice === "dark") {
      root.setAttribute("data-theme", choice);
    } else {
      root.removeAttribute("data-theme");
    }
    var buttons = form.querySelectorAll(".theme-btn");
    for (var i = 0; i < buttons.length; i += 1) {
      var pressed = buttons[i].value === choice ||
        (choice === "system" && buttons[i].value === "system");
      buttons[i].setAttribute("aria-pressed", pressed ? "true" : "false");
    }
  }

  form.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("button[name='theme']") : null;
    if (!button) return;
    event.preventDefault();

    paint(button.value);

    var payload = new FormData(form);
    payload.set("theme", button.value);
    fetch(form.action, {
      method:      "POST",
      body:        payload,
      credentials: "same-origin",
      redirect:    "manual",
    }).catch(function () {
      // allow:swallow-unverified this file is a browser island. The coverage
      // run is c8 over a Node process, which never loads it, so nothing under
      // lib/web/public/islands appears in the coverage report at all and no
      // test in this harness can drive this catch. The recovery is not silent:
      // it falls back to the plain form post, which is the same request without
      // fetch, and the server answers it the same way.
      //
      // The preference did not reach the server, so the next page load
      // would contradict what is on screen. Let the plain form carry it.
      form.submit();
    });
  });
}());
