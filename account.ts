import assert from "assert";

const accounts = [
  {
    id: "23121d3c-84df-44ac-b458-3d63a9a05497",
    email: "foo@example.com",
    email_verified: true,
  },
  {
    id: "c2ac2b4a-2262-4e2f-847a-a40dd3c4dcd5",
    email: "bar@example.com",
    email_verified: false,
  },
];

class Account {
  static async findAccount(ctx, id) {
    const account = accounts.find(
      (account) => account.id == id,
    );

    if (!account) {
      return undefined;
    }

    return {
      accountId: id,
      async claims() {
        return {
          sub: id,
          email: account.email,
          email_verified: account.email_verified,
        };
      },
    };
  }

  static async authenticate(email, password) {
    try {
      assert(
        password,
        "password must be provided",
      );
      assert(email, "email must be provided");
      const lowercased =
        String(email).toLowerCase();
      const account = accounts.find(
        (account) => account.email == lowercased,
      );

      assert(
        account,
        "invalid credentials provided",
      );

      return account.id;
    } catch (err) {
      return undefined;
    }
  }
}

export default Account;
