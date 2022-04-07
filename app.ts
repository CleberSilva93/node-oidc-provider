const { Provider } = require("oidc-provider");
const assert = require("assert");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
import Account from "./account";

var app = express();
app.set("trust proxy", true);
app.set("view engine", "ejs");
app.set(
  "views",
  path.resolve(__dirname, "views"),
);

const parse = bodyParser.urlencoded({
  extended: false,
});

function setNoCache(req, res, next) {
  res.set("Pragma", "no-cache");
  res.set("Cache-Control", "no-cache, no-store");
  next();
}

const clients = [
  {
    client_id: "client_id_1",
    client_secret: "client_secret_1",
    redirect_uris: [
      "https://oidcdebugger.com/debug",
    ],
    response_type: [
      "code",
      // "id_token",
      // "code id_token",
    ],
    grant_types: [
      "authorization_code",
      "implicit",
    ],
  },

  {
    client_id: "client_id_2",
    client_secret: "client_secret_2",
    redirect_uris: [
      "https://oidcdebugger.com/debug",
    ],
    response_type: [
      "code",
      // "id_token",
      // "code id_token",
    ],
    grant_types: [
      "authorization_code",
      "implicit",
    ],
  },
];

const oidc = new Provider(
  "https://localhost:3000",
  {
    clients,
    features: {
      clientCredentials: { enabled: true },
      devInteractions: { enabled: false },
    },
    issueRefreshToken: async (
      ctx,
      client,
      code,
    ) => {
      console.log(ctx, client, code);
      return true;
    },

    interactions: {
      url(ctx, interaction) {
        console.log({ interaction });
        return `/interaction/${interaction.uid}`;
      },
    },
    findAccount: Account.findAccount,
    pkce: {
      required: (ctx, client) => {
        return false;
      },
    },
    renderError: (ctx, out, error) => {
      console.log({ error });
      return { ctx, out, error };
    },
    claims: {
      email: ["email", "email_verified"],
      phone: [
        "phone_number",
        "phone_number_verified",
      ],
      profile: [
        "birthdate",
        "family_name",
        "gender",
        "given_name",
        "locale",
        "middle_name",
        "name",
        "nickname",
        "picture",
        "preferred_username",
        "profile",
        "updated_at",
        "website",
        "zoneinfo",
      ],
    },
  },
);

app.get(
  "/interaction/:uid",
  setNoCache,
  async (req, res, next) => {
    try {
      const details =
        await oidc.interactionDetails(req, res);
      console.log(
        "see what else is available to you for interaction views",
        details,
      );
      const { uid, prompt, params } = details;
      const client = await oidc.Client.find(
        params.client_id,
      );

      if (prompt.name === "login") {
        return res.render("login", {
          client,
          uid,
          details: prompt.details,
          params,
          title: "Sign-in",
          flash: undefined,
        });
      }

      return res.render("interaction", {
        client,
        uid,
        details: prompt.details,
        params,
        title: "Authorize",
      });
    } catch (err) {
      return next(err);
    }
  },
);

app.post(
  "/interaction/:uid/login",
  setNoCache,
  parse,
  async (req, res, next) => {
    try {
      const { uid, prompt, params } =
        await oidc.interactionDetails(req, res);
      assert.strictEqual(prompt.name, "login");
      const client = await oidc.Client.find(
        params.client_id,
      );

      const accountId =
        await Account.authenticate(
          req.body.email,
          req.body.password,
        );

      if (!accountId) {
        res.render("login", {
          client,
          uid,
          details: prompt.details,
          params: {
            ...params,
            login_hint: req.body.email,
          },
          title: "Sign-in",
          flash: "Invalid email or password.",
        });
        return;
      }

      const result = {
        login: { accountId },
      };

      await oidc.interactionFinished(
        req,
        res,
        result,
        { mergeWithLastSubmission: false },
      );
    } catch (err) {
      next(err);
    }
  },
);

app.post(
  "/interaction/:uid/confirm",
  setNoCache,
  parse,
  async (req, res, next) => {
    try {
      const interactionDetails =
        await oidc.interactionDetails(req, res);
      const {
        prompt: { name, details },
        params,
        session: { accountId },
      } = interactionDetails;
      assert.strictEqual(name, "consent");

      let { grantId } = interactionDetails;
      let grant;

      if (grantId) {
        grant = await oidc.Grant.find(grantId);
      } else {
        grant = new oidc.Grant({
          accountId,
          clientId: params.client_id,
        });
      }

      if (details.missingOIDCScope) {
        grant.addOIDCScope(
          details.missingOIDCScope.join(" "),
        );
      }
      if (details.missingOIDCClaims) {
        grant.addOIDCClaims(
          details.missingOIDCClaims,
        );
      }
      if (details.missingResourceScopes) {
        for (const [
          indicator,
          scopes,
        ] of Object.entries(
          details.missingResourceScopes,
        )) {
          const scopesS: any = scopes;
          grant.addResourceScope(
            indicator,
            scopesS.join(" "),
          );
        }
      }

      grantId = await grant.save();

      const consent: any = {};
      if (!interactionDetails.grantId) {
        consent.grantId = grantId;
      }

      const result = { consent };
      await oidc.interactionFinished(
        req,
        res,
        result,
        { mergeWithLastSubmission: true },
      );
    } catch (err) {
      next(err);
    }
  },
);

app.get(
  "/interaction/:uid/abort",
  setNoCache,
  async (req, res, next) => {
    try {
      const result = {
        error: "access_denied",
        error_description:
          "End-User aborted interaction",
      };
      await oidc.interactionFinished(
        req,
        res,
        result,
        { mergeWithLastSubmission: false },
      );
    } catch (err) {
      next(err);
    }
  },
);

app.use(oidc.callback());

app.get("/sample", function (req, res) {
  console.log({ req });
  res.send("hello world");
});

app.listen(3000, () => {
  console.log(
    "oidc-provider listening on port 3000, check http://localhost:3000/.well-known/openid-configuration",
  );
});
