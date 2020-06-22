'use strict';
import styles from './../css/signup.css';
import image from './../admin-tool.png';
const m = require("mithril");

const root = document.body;

function main() {
    
  m.render(root, m("div.formcontainer",
  [
        m("label","Signup to Site"),
        m("form.loginform[action='api/signup'][method='post']",
        [
            m("label[for='name']","Name"),
            m("br"),
            m("input#name.forminput[type=text][name='name']"),
            m("br"),
            m("label[for='email']","Email"),
            m("br"),
            m("input#email.forminput[type=email][name='email']"),
            m("br"),
            m("label[for='pwd']","Password"),
            m("br"),
            m("input#pwd.forminput[type=password][name='pwd']"),
            m("br"),
            m("input.button[type=submit][value='Signup']"),
        ]),
  ]
  ));
}

window.onload = main;