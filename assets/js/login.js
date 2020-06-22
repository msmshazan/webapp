'use strict';
import styles from './../css/login.css';
import image from './../admin-tool.png';
const m = require("mithril");

const root = document.body;

function main() {
    
  m.render(root, m("div.formcontainer",
  [
        m("label","Login to Site"),
        m("form.loginform[action='api/login'][method='post']",
        [
            m("label[for='name']","Name"),
            m("br"),
            m("input#name.forminput[type=text][name='name']"),
            m("br"),
            m("label[for='pwd']","Password"),
            m("br"),
            m("input#pwd.forminput[type=password][name='pwd']"),
            m("br"),
            m("input.button[type=submit][value='Login']"),
        ]),
  ]
  ));
}

window.onload = main;