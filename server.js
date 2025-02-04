const express = require("express");
const axios = require("axios");const crypto = require("crypto");
const cors = require("cors");

require("dotenv").config();

const app = express();
const PORT = 4242;

// Middleware
app.use(cors());
const corsOptions = {
  origin: "*", // Allow all origins
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE", // Allow all standard methods
  allowedHeaders: ["Content-Type", "Authorization"], // Specify allowed headers
};

app.use(cors(corsOptions));
app.use(express.json());



app.get("/health", (req, res) => {
console.log('Request headers:', req.headers); 
 res.json({ message: "Server Health is Fine" });
});

// Salesforce Config
const BASE_URL = process.env.API_SALESFORCE_INSTATE;
const API_VERSION = process.env.API_VERSION || "v57.0";
const DOMAIN = process.env.DOMAIN || "localhost:5173";
let accessToken = null;

// Salesforce Access Token Refresh
const refreshAccessToken = async () => {
  console.log("refreshAccessToken");
  try {
    const response = await axios.post(
      `${BASE_URL}/services/oauth2/token`,
      null,
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        params: {
          grant_type: "password",
          client_id: process.env.API_SALESFORCE_CLIENT_ID,
          client_secret: process.env.API_SALESFORCE_CLIENT_SECRET,
          username: process.env.API_SALESFORCE_USER_NAME,
          password: process.env.API_SALESFORCE_USER_PASSWORD,
        },
      }
    );
    // console.log(response);
    accessToken = response.data.access_token;
    console.log("accessToken", accessToken);
  } catch (error) {
    throw new Error("Failed to refresh Salesforce access token");
  }
};

// Ensure Salesforce Access Token Middleware
const ensureSalesforceAccessToken = async (req, res, next) => {
  try {
    await refreshAccessToken();
    console.log("Access Token Refreshed");
    req.headers["Authorization"] = `Bearer ${accessToken}`;
    next();
  } catch (error) {
    res.status(500).json({ message: "Salesforce authentication error", error });
  }
};

// Salesforce Helper
const salesforceRequest = async (method, endpoint, data = {}) => {
  try {
    const url = `${BASE_URL}/services/data/${API_VERSION}/${endpoint}`;
    const response = await axios({
      method,
      url,
      headers: { Authorization: `Bearer ${accessToken}` },
      data,
    });
    return response.data;
  } catch (error) {
    throw error.response ? error.response.data : error;
  }
};

// Utility Functions
const encryptVal = (clearText) => {
  return Buffer.from(clearText).toString("base64");
};

const decryptVal = (cipherText) => {
  return Buffer.from(cipherText, "base64").toString("utf-8");
};

const generateActivationToken = (email) => {
  const timestamp = Math.floor(Date.now() / 1000);
  return crypto
    .createHash("sha256")
    .update(`${email}${timestamp}`)
    .digest("hex");
};

const getPublicIp = () => {
  try {
    const output = execSync("curl http://checkip.dyndns.com/").toString();
    const ip = output.match(/Address: (\d+\.\d+\.\d+\.\d+)/)[1];
    return ip;
  } catch (error) {
    console.error("Failed to fetch public IP:", error);
    return null;
  }
};

// Routes
// 1. Profile Login
app.post("/api/auth/login", ensureSalesforceAccessToken, async (req, res) => {
  console.log("req.body", req.body);
  const { email, password } = req.body;
  console.log(email, password);

  try {
    // Validate reCAPTCHA
    // const recaptchaResponse = false;

    // if (!recaptchaResponse.data.success) {
    //   return res.status(400).json({ message: "reCAPTCHA verification failed" });
    // }
    //const recaptchaResponse = false;

    //    if (!recaptchaResponse.data.success) {
    //    return res.status(400).json({ message: "reCAPTCHA verification failed" });
    // }

    // Query Contact
    const contactQuery = `SELECT Id, Password__c, Is_Email_Verify__c, CHF_Account_Status__c, FIRSTNAME, LASTNAME FROM Contact WHERE Email = '${email}'`;
    const contact = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(contactQuery)}`
    );
    console.log(contact);

    if (contact.totalSize === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const contactRecord = contact.records[0];
    console.log(contactRecord);

    if (
      contactRecord.CHF_Account_Status__c !== "Approve" ||
      !contactRecord.Is_Email_Verify__c
    ) {
      return res
        .status(403)
        .json({ message: "Account not verified or approved" });
    }

    const decryptedPassword = decryptVal(contactRecord.Password__c);
    //    const decryptedPassword = decryptVal(contactRecord.Password__c);
    console.log("decryptedPassword", decryptedPassword);

    if (decryptedPassword !== password) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    console.log({
      message: "Login successful",
      data: {
        userId: contactRecord.Id,
        email,
        firstName: contactRecord.FirstName,
        lastName: contactRecord.LastName,
      },
      success: true,
    });

    res.status(200).json({
      message: "Login successful",
      data: {
        userId: contactRecord.Id,
        email,
        firstName: contactRecord,
        lastName: contactRecord,
      },
      success: true,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Login failed", error });
  }
});

//2. Profile Register/ Create Profile
app.post(
  "/api/auth/register",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const {
      firstname,
      lastname,
      emailid,
      usernumber,
      userpwd,
      userconfirmPassword,
      // qt_hiddenRecaptchaToken_signup,
    } = req.body;

    if (userpwd !== userconfirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    try {
      // Validate reCAPTCHA
      // const recaptchaResponse = await axios.post(
      //   "https://www.google.com/recaptcha/api/siteverify",
      //   null,
      //   {
      //     params: {
      //       secret: process.env.RECAPTCHA_SECRET_KEY,
      //       response: qt_hiddenRecaptchaToken_signup,
      //     },
      //   }
      // );

      // if (false) {
      //   return res
      //     .status(400)
      //     .json({ message: "reCAPTCHA verification failed" });
      // }

      // Check if Contact exists
      const recordTypeQuery =
        "SELECT Id FROM RecordType WHERE Name = 'Household Account'";
      const recordType = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(recordTypeQuery)}`
      );

      const contactQuery = `SELECT Id FROM Contact WHERE Account.RecordTypeId = '${recordType.records[0].Id}' AND Email = '${emailid}'`;
      const contactExists = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(contactQuery)}`
      );

      if (contactExists.totalSize > 0) {
        return res.status(400).json({ message: "Email already exists" });
      }

      // Create Contact
      // const domain = req.get("host");
      const activationLink = `http://${DOMAIN}/activate/${Buffer.from(
        emailid
      ).toString("base64")}/${generateActivationToken(emailid)}`;

      const data = await salesforceRequest("POST", "sobjects/Contact", {
        FirstName: firstname,
        LastName: lastname,
        Email: emailid,
        Phone: usernumber,
        Password__c: encryptVal(userpwd),
        Activate_Link__c: activationLink,
      });

      res.status(201).json({
        message: "Registration successful",
        success: true,
        data,
        activationLink,
      });
    } catch (error) {
      res.status(500).json({ message: "Registration failed", error });
    }
  }
);

// 3. Profile Activate
app.get(
  "/activate/:uidb64/:token",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const { uidb64, token } = req.params;
    const email = Buffer.from(uidb64, "base64").toString("utf-8");

    try {
      const contactQuery = `SELECT Id, Is_Email_Verify__c FROM Contact WHERE Email = '${email}'`;
      const contact = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(contactQuery)}`
      );

      if (contact.totalSize === 0 || contact.records[0].Is_Email_Verify__c) {
        return res
          .status(400)
          .json({ message: "Inavlid Link.", success: false, error: error });
      }

      await salesforceRequest(
        "PATCH",
        `sobjects/Contact/${contact.records[0].Id}`,
        {
          Is_Email_Verify__c: true,
        }
      );

      // res.redirect("/login");
      res.status(201).json({
        message: "Email activation successful",
        success: true,
      });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Activation failed", success: false, error: error });
    }
  }
);

// 4. Profile Check Email
app.post(
  "/api/auth/check-email",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const { forgot_email } = req.body;
    try {
      const recordTypeQuery =
        "SELECT Id FROM RecordType WHERE Name = 'Household Account'";
      const recordType = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(recordTypeQuery)}`
      );

      const contactQuery = `SELECT Id, CHF_Account_Status__c, Is_Email_Verify__c FROM Contact WHERE Email = '${forgot_email}' AND Account.RecordTypeId = '${recordType.records[0].Id}'`;
      const contact = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(contactQuery)}`
      );

      if (contact.totalSize === 0) {
        return res.status(404).json({ message: "Email not registered" });
      }

      const contactRecord = contact.records[0];

      if (contactRecord.CHF_Account_Status__c === "Reject") {
        return res.status(403).json({ message: "User is locked" });
      }

      if (!contactRecord.Is_Email_Verify__c) {
        return res.status(403).json({ message: "Email not verified" });
      }

      // const domain = req.get("host");
      const resetPwdLink = `http://${DOMAIN}/reset-password/${Buffer.from(
        forgot_email
      ).toString("base64")}/${generateActivationToken(forgot_email)}`;

      await salesforceRequest("PATCH", `sobjects/Contact/${contactRecord.Id}`, {
        Reset_Pwd_Link__c: resetPwdLink,
      });

      res.status(200).json({
        message: "Password reset link is sent to the regesterd email",
        success: true,
        link: resetPwdLink,
      });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Check email failed", error, success: false });
    }
  }
);

// 5. Profile Reset Password
app.post(
  "/api/auth/reset-password",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const { email, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    try {
      // const email = Buffer.from(uidb64, "base64").toString("utf-8");

      const contactQuery = `SELECT Id FROM Contact WHERE Email = '${email}'`;
      const contact = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(contactQuery)}`
      );

      if (contact.totalSize === 0) {
        return res.status(404).json({ message: "Invalid credentials" });
      }

      await salesforceRequest(
        "PATCH",
        `sobjects/Contact/${contact.records[0].Id}`,
        {
          // Password__c: newPassword,
          Password__c: encryptVal(newPassword),
        }
      );

      res
        .status(200)
        .json({ message: "Password reset successful", success: true });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Reset password failed", success: false, error });
    }
  }
);

// 6. Profile Forgot Password
app.post(
  "/api/auth/forgot-password",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const { uidb64, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    try {
      const email = Buffer.from(uidb64, "base64").toString("utf-8");

      const contactQuery = `SELECT Id FROM Contact WHERE Email = '${email}'`;
      const contact = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(contactQuery)}`
      );

      if (contact.totalSize === 0) {
        return res.status(404).json({ message: "Invalid reset link" });
      }

      await salesforceRequest(
        "PATCH",
        `sobjects/Contact/${contact.records[0].Id}`,
        {
          Password__c: encryptVal(newPassword),
        }
      );

      res
        .status(200)
        .json({ message: "Password reset successful", success: true });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Reset password failed", error, success: false });
    }
  }
);

// 7. Profile Update/Create
app.post(
  "/api/profile/update",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const { firstName, lastName, mobile, Id } = req.body;

    try {
      const contactId = Id;

      await salesforceRequest("PATCH", `sobjects/Contact/${contactId}`, {
        FirstName: firstName,
        LastName: lastName,
        MobilePhone: mobile,
      });

      res.status(200).json({
        message: "Profile updated successfully",
        success: true,
        userData: { firstName, lastName, mobile },
      });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Profile update failed", error, success: false });
    }
  }
);

// 8. Add members
app.post("/api/member/add", ensureSalesforceAccessToken, async (req, res) => {
  const {
    relName,
    memFname,
    memLname,
    memEmailAddr,
    memMobile,
    memDOB,
    memCreateAcc,
    useremail,
    contactId,
  } = req.body;
  const memHidId = contactId;

  try {
    // Fetch account ID and household name using useremail
    const contactQuery = `SELECT AccountId FROM Contact WHERE Email = '${useremail}'`;
    const contactResult = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(contactQuery)}`
    );

    if (contactResult.totalSize === 0) {
      return res.status(404).json({ message: "User email not found." });
    }

    const accountId = contactResult.records[0].AccountId;

    const accountQuery = `SELECT Name FROM Account WHERE Id = '${accountId}'`;
    const accountResult = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(accountQuery)}`
    );

    if (accountResult.totalSize === 0) {
      return res.status(404).json({ message: "Account not found." });
    }

    const householdName = accountResult.records[0].Name;

    // Check if memHidId is provided for update
    if (memHidId) {
      const checkContactQuery = `SELECT Id FROM Contact WHERE Id = '${memHidId}' AND Account.RecordTypeId = '${accountId}'`;
      const checkContact = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(checkContactQuery)}`
      );

      if (checkContact.totalSize === 0) {
        return res
          .status(404)
          .json({ message: "No matching contact found to update." });
      }

      const formattedDOB = memDOB.split("/").reverse().join("-");

      await salesforceRequest("PATCH", `sobjects/Contact/${memHidId}`, {
        FirstName: memFname,
        LastName: memLname,
        MobilePhone: memMobile,
        Birthdate: formattedDOB,
        Member_Relationship__c: relName,
        Member_Account__c: memCreateAcc === "Yes",
        Household__c: householdName,
      });

      return res.status(200).json({ message: "Member updated successfully." });
    }

    // Check if Contact already exists
    const existingContactQuery = `SELECT Id FROM Contact WHERE Account.RecordTypeId = '${accountId}' AND Email = '${memEmailAddr}'`;
    const contactExists = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(existingContactQuery)}`
    );

    if (contactExists.totalSize > 0) {
      return res
        .status(400)
        .json({ message: "This email already exists with another account." });
    }

    // Prepare additional fields
    const curYear = new Date().getFullYear();
    const pwd = `Chfusa${curYear}!`;
    const password = encryptVal(pwd);

    const activationLink =
      memCreateAcc === "Yes"
        ? `http://${req.get("host")}/chfusa/activate/${Buffer.from(
            memEmailAddr
          ).toString("base64")}/${generateActivationToken(memEmailAddr)}`
        : "";

    const resetPwdLink =
      memCreateAcc === "Yes"
        ? `http://${req.get("host")}/resetpassword/${Buffer.from(
            memEmailAddr
          ).toString("base64")}/${generateActivationToken(memEmailAddr)}`
        : "";

    const formattedDOB = memDOB.split("/").reverse().join("-");

    // Create new member
    await salesforceRequest("POST", "sobjects/Contact", {
      FirstName: memFname,
      LastName: memLname,
      Email: memEmailAddr,
      MobilePhone: memMobile,
      AccountId: accountId,
      Password__c: password,
      Birthdate: formattedDOB,
      Member_Relationship__c: relName,
      Member_Account__c: memCreateAcc === "Yes",
      Activate_Link__c: activationLink,
      Base_URL__c: `http://${req.get("host")}`,
      Is_Email_Verify__c: true,
      Is_Member_Email__c: true,
      CHF_Account_Status__c: "Approve",
      Reset_Pwd_Link__c: resetPwdLink,
      Household__c: householdName,
    });

    res.status(201).json({ message: "Member added successfully." });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong, please try again later.",
      error,
    });
  }
});

// 9. Delete Member
app.post(
  "/api/delete-member",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const {
      memberId, // ID of the member to be deleted
      contactId, // ID of the account associated with the member
    } = req.body;

    const query = `SELECT ID, ACCOUNT.ID FROM Contact WHERE Id = '${contactId}'`;
    const contactData = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(query)}`
    );

    try {
      // Update the member's status to "Reject" and clear their email
      await salesforceRequest("PATCH", `sobjects/Contact/${memberId}`, {
        CHF_Account_Status__c: "Reject", // Mark the member as rejected
        Email: "", // Remove email from the member record
      });

      // Fetch the list of remaining approved members for the account
      const memberQuery = `SELECT Id, FirstName, LastName FROM Contact WHERE AccountId = '${contactData?.records[0]?.Account?.Id}' AND CHF_Account_Status__c = 'Approve'`;
      const updatedMembers = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(memberQuery)}`
      );

      res.status(200).json({
        message: "Member deleted successfully.",
        members: updatedMembers.records, // Return the updated list of members
        success: true,
      });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Error deleting member.", error, success: false });
    }
  }
);

// 10. Donations Initial opportunity creation
app.post(
  "/api/donate/create",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const {
      donAmt, // Total donation amount
      donorName, // Full name of the donor
      displayName, // Display name for the donation record
      donorEmail, // Donor's email
      donorMobile, // Donor's mobile number
      donorBillSt, // Donor's billing street
      donorCity, // Donor's billing city
      donorState, // Donor's billing state
      donorZip, // Donor's billing zip/postal code
      donorCountry, // Donor's billing country
      tnxId, // Transaction ID or payment mode
      donationCategories, // Array of donation category objects
    } = req.body;

    let accountId = req.session?.accountId || null;
    let donorFirstName = "";
    let donorLastName = "";
    let contRecId = null;
    let stageName = "Payment Pending";
    // let stageName = "Payment Pending";
    let Transaction_ID__c = tnxId;

    try {
      const todayDate = new Date().toISOString().split("T")[0]; // Format: YYYY-MM-DD

      // Split donor name into first and last name
      if (donorName.includes(" ")) {
        const nameParts = donorName.split(" ");
        donorLastName = nameParts.pop();
        donorFirstName = nameParts.join(" ");
      } else {
        donorFirstName = donorName;
        donorLastName = donorName;
      }

      // Adjust stage name based on transaction ID
      if (tnxId === "cheque") {
        stageName = "Payment Pending";
        Transaction_ID__c = `Check-${generateRandomString(12)}`;
      } else if (tnxId === "zelle") {
        stageName = "Payment Pending";
        Transaction_ID__c = `Zelle-${generateRandomString(13)}`;
      }else{
        stageName = "Payment Pending";
        Transaction_ID__c = `Online-${generateRandomString(13)}`;
      }
      console.log(
        "displayName: " + displayName,
        "tnxId: " + tnxId,
        "stageName: " + stageName,
        "Transaction_ID__c: " + Transaction_ID__c
      );

      // Check if donor exists
      const contactQuery = `SELECT Id, Name, AccountId FROM Contact WHERE Email = '${donorEmail}'`;
      const contact = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(contactQuery)}`
      );

      if (contact.totalSize > 0) {
        const donorRecord = contact.records[0];
        accountId = donorRecord.AccountId;
        contRecId = donorRecord.Id;
      } else {
        // Create new donor contact
        const contactData = {
          FirstName: donorFirstName,
          LastName: donorLastName,
          Email: donorEmail,
          MobilePhone: donorMobile,
        };
        const newContact = await salesforceRequest(
          "POST",
          "sobjects/Contact",
          contactData
        );
        contRecId = newContact.id;

        // Update donor's account with billing details
        const accountQuery = `SELECT AccountId FROM Contact WHERE Id = '${newContact.id}'`;
        const account = await salesforceRequest(
          "GET",
          `query?q=${encodeURIComponent(accountQuery)}`
        );
        accountId = account.records[0].AccountId;

        const accountData = {
          BillingStreet: donorBillSt,
          BillingCity: donorCity,
          BillingState: donorState,
          BillingPostalCode: donorZip,
          BillingCountry: donorCountry,
        };
        await salesforceRequest(
          "PATCH",
          `sobjects/Account/${accountId}`,
          accountData
        );
      }

      // Create donation opportunity
      const recordTypeQuery = `SELECT Id FROM RecordType WHERE Name = 'Donation'`;
      const recordType = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(recordTypeQuery)}`
      );

      const opportunityData = {
        AccountId: accountId,
        Amount: donAmt,
        StageName: stageName,
        CloseDate: todayDate,
        Name: displayName,
        Donor__c: contRecId,
        RecordTypeId: recordType.records[0].Id,
        // Description: donationCategories?.toString(),
      };
      const opportunity = await salesforceRequest(
        "POST",
        "sobjects/Opportunity",
        opportunityData
      );

      // Process donation categories
      // for (const category of donationCategories) {
      //   const { projectName, unitAmount, quantity, remark } = category;

      //   if (unitAmount) {
      //     const donationSummaryData = {
      //       Opportunity__c: opportunity.id,
      //       Campaign_Name__c: projectName,
      //       Amount__c: unitAmount,
      //       Quantity__c: quantity,
      //       Remark__c: remark,
      //     };

      //     await salesforceRequest(
      //       "POST",
      //       "sobjects/DonationSummary__c",
      //       donationSummaryData
      //     );
      //   }
      // }

      // const pLimit = (await import("p-limit")).default;
      // // Let's say we allow 3 concurrent requests at a time
      // const limit = pLimit(10);

      // // Filter categories to only those that have a unitAmount
      // const categoriesToCreate = donationCategories.filter(
      //   (category) => category.unitAmount
      // );

      // const promises = categoriesToCreate.map((category) =>
      //   limit(async () => {
      //     const { projectName, unitAmount, quantity, remark } = category;
      //     const donationSummaryData = {
      //       Opportunity__c: opportunity.id,
      //       Campaign_Name__c: projectName,
      //       Amount__c: unitAmount,
      //       Quantity__c: quantity,
      //       Remark__c: remark,
      //     };

      //     return salesforceRequest(
      //       "POST",
      //       "sobjects/DonationSummary__c",
      //       donationSummaryData
      //     );
      //   })
      // );

      // const results = await Promise.allSettled(promises);

      // // In case you want to know if anything failed or succeeded
      // const successes = [];
      // const failures = [];

      // results.forEach((res, i) => {
      //   if (res.status === "fulfilled") {
      //     successes.push(res.value);
      //   } else {
      //     failures.push({ index: i, reason: res.reason });
      //   }
      // });
      // console.log("Successful donation summaries:", successes, failures);
      // const donationSummaries = donationCategories.map((category) => ({
      //   Opportunity__c: opportunity.id,
      //   Campaign_Name__c: category.projectName,
      //   Amount__c: category.unitAmount,
      //   Quantity__c: category.quantity,
      //   Remark__c: category.remark,
      // }));
      // console.log(donationSummaries);

      // const sum_resp = await salesforceRequest("POST", "composite/sobjects", {
      //   records: donationSummaries,
      // });
      // console.log(sum_resp[0].errors);
      // Utility function to create a delay
      // const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

      // const categoriesToCreate = donationCategories.filter(
      //   (category) => category.unitAmount
      // );

      // // Run promises with delay
      // for (const [index, category] of categoriesToCreate.entries()) {
      //   const { projectName, unitAmount, quantity, remark } = category;
      //   const donationSummaryData = {
      //     Opportunity__c: opportunity.id,
      //     Campaign_Name__c: projectName,
      //     Amount__c: unitAmount,
      //     Quantity__c: quantity,
      //     Remark__c: remark,
      //   };

      //   // Add delay before making the request
      //   if (index > 0) await delay(100); // Delay for subsequent requests

      //   await salesforceRequest(
      //     "POST",
      //     "sobjects/DonationSummary__c",
      //     donationSummaryData
      //   );
      // }
      const compositePayload = {
        batchRequests: donationCategories.map((category) => ({
          method: "POST",
          url: `/services/data/${API_VERSION}/sobjects/DonationSummary__c`,
          richInput: {
            Opportunity__c: opportunity.id,
            Campaign_Name__c: category.projectName,
            Amount__c: category.unitAmount,
            Quantity__c: category.quantity,
            Remark__c: category.remark,
          },
        })),
      };

      // Send the batch request to Salesforce
      const compositeResponse = await salesforceRequest(
        "POST",
        "composite/batch",
        compositePayload
      );

      // Handle responses
      compositeResponse.results.forEach((result, index) => {
        if (result.statusCode >= 400) {
          console.error(
            `Failed for category: ${donationCategories[index].projectName}`,
            result.result
          );
        } else {
          console.log(
            `Success for category: ${donationCategories[index].projectName}`
          );
        }
      });

      // Update opportunity with transaction details
      await salesforceRequest(
        "PATCH",
        `sobjects/Opportunity/${opportunity.id}`,
        {
          Transaction_ID__c: Transaction_ID__c,
          EmailTriggered__c: false,
        }
      );

      res.status(200).json({
        message: "Donation processed successfully.",
        success: true,
        opportunity: opportunity.id,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        message: "Failed to process donation.",
        error,
        success: false,
      });
    }
  }
);

//11. join Newsletter
app.post("/api/newsletter", ensureSalesforceAccessToken, async (req, res) => {
  const { SubscriberEmail } = req.body;

  try {
    // Get Subscriber IP Address
    const SubscriberIPAddress = getPublicIp();
    if (!SubscriberIPAddress) {
      return res
        .status(500)
        .json({ message: "Unable to fetch public IP address." });
    }

    // Check if already subscribed
    const newsletterQuery = `SELECT Subscriber_Email__c FROM Newsletter__c WHERE Subscriber_Email__c = '${SubscriberEmail}'`;
    const newsletterRec = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(newsletterQuery)}`
    );

    if (newsletterRec.totalSize > 0) {
      return res
        .status(400)
        .json({ message: "Already Subscribed!", success: false });
    }

    // Add subscription
    await salesforceRequest("POST", "sobjects/Newsletter__c", {
      Subscriber_Email__c: SubscriberEmail,
      Subscriber_IP_Address__c: SubscriberIPAddress,
    });

    res
      .status(201)
      .json({ message: "Subscribed Successfully.", success: true });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong, please try again later.",
      error,
      success: false,
    });
  }
});

// Helper function to generate a random string
const generateRandomString = (length) => {
  return Array(length)
    .fill(null)
    .map(() =>
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ".charAt(Math.floor(Math.random() * 26))
    )
    .join("");
};

// ========== STRIPE CODE (UNCHANGED) ==========
const stripe = require("stripe")(`${process.env.VITE_STRIPE_CLIENT_SECRET}`);

console.log("VITE_STRIPE_CLIENT_SECRET", process.env.VITE_STRIPE_CLIENT_SECRET);

const calculateOrderAmount = (items) => {
  let total = 0;
  items.forEach((item) => {
    total += item.amount;
  });
  return total;
};

app.post("/create-payment-intent", async (req, res) => {
  const { items } = req.body;
  console.log("🚀 ~ app.post ~ items:", items);

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: calculateOrderAmount(items),
      currency: "usd",
      automatic_payment_methods: { enabled: true },
    });

    // Return client secret only
    res.status(200).send({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    res.status(500).send(error);
  }
});
// ========== END STRIPE CODE ==========

// ========== SALESFORCE ROUTES (with ensureSalesforceAccessToken) ==========

// 12. Profile Get Profile details
app.get("/api/contact", ensureSalesforceAccessToken, async (req, res) => {
  try {
    const email = req.query.email;
    const query = `SELECT ID, EMAIL, FIRSTNAME, LASTNAME, PHONE, ACCOUNT.ID FROM Contact WHERE Email = '${email}'`;
    const data = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(query)}`
    );
    console.log("data", data?.records[0]);
    const query1 = `SELECT ID, BILLINGSTREET, BILLINGCITY, BILLINGSTATE, BILLINGCOUNTRY, BILLINGPOSTALCODE, SHIPPINGSTREET,SHIPPINGCITY,SHIPPINGCOUNTRY, SHIPPINGSTATE, SHIPPINGPOSTALCODE FROM Account WHERE Id = '${data?.records[0]?.Account?.Id}'`;
    const data1 = await salesforceRequest(
      "GET",
      `query?q=${encodeURIComponent(query1)}`
    );
    const sameAddress =
      data1?.records[0]?.BillingStreet === data1?.records[0]?.ShippingStreet &&
      data1?.records[0]?.BillingCity === data1?.records[0]?.ShippingCity &&
      data1?.records[0]?.BillingCountry ===
        data1?.records[0]?.ShippingCountry &&
      data1?.records[0]?.BillingState === data1?.records[0]?.ShippingState &&
      data1?.records[0]?.BillingPostalCode ===
        data1?.records[0]?.ShippingPostalCode;
    console.log(sameAddress);

    res.json({
      firstName: data?.records[0]?.FirstName,
      lastName: data?.records[0]?.LastName,
      email: data?.records[0]?.Email,
      mobile: data?.records[0]?.Phone,
      billingStreet: data1?.records[0]?.BillingStreet,
      billingCity: data1?.records[0]?.BillingCity,
      billingState: data1?.records[0]?.BillingState,
      billingCountry: data1?.records[0]?.BillingCountry,
      billingPostalCode: data1?.records[0]?.BillingPostalCode,
      shippingStreet: data1?.records[0]?.ShippingStreet,
      shippingCity: data1?.records[0]?.ShippingCity,
      shippingCountry: data1?.records[0]?.ShippingCountry,
      shippingState: data1?.records[0]?.ShippingState,
      shippingPostalCode: data1?.records[0]?.ShippingPostalCode,
      sameAddress,
    });
  } catch (error) {
    res.status(500).json(error);
  }
});

app.get("/", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.json({ user: "admin" });
});

// 2. Contact Create
app.post("/api/contact", ensureSalesforceAccessToken, async (req, res) => {
  try {
    const data = await salesforceRequest("POST", "sobjects/Contact", req.body);
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json(error);
  }
});

// 3. Profile Address Update
app.patch(
  "/api/profile/address",
  ensureSalesforceAccessToken,
  async (req, res) => {
    const { contactId } = req.body;
    try {
      // const accountId = req.params.id;
      const query = `SELECT ID, ACCOUNT.ID FROM Contact WHERE Id = '${contactId}'`;
      const contactData = await salesforceRequest(
        "GET",
        `query?q=${encodeURIComponent(query)}`
      );
      console.log({
        BillingCity: req.body.billingCity,
        BillingCountry: req.body.billingCountry,
        BillingPostalCode: req.body.billingPostalCode,
        BillingState: req.body.billingState,
        BillingStreet: req.body.billingStreet,
        ShippingCity: req.body.shippingCity,
        ShippingCountry: req.body.shippingCountry,
        ShippingPostalCode: req.body.shippingPostalCode,
        ShippingState: req.body.shippingState,
        ShippingStreet: req.body.shippingStreet,
      });
      const data = await salesforceRequest(
        "PATCH",
        `sobjects/Account/${contactData?.records[0]?.Account?.Id}`,
        {
          BillingCity: req.body.billingCity,
          BillingCountry: req.body.billingCountry,
          BillingPostalCode: req.body.billingPostalCode,
          BillingState: req.body.billingState,
          BillingStreet: req.body.billingStreet,
          ShippingCity: req.body.shippingCity,
          ShippingCountry: req.body.shippingCountry,
          ShippingPostalCode: req.body.shippingPostalCode,
          ShippingState: req.body.shippingState,
          ShippingStreet: req.body.shippingStreet,
        }
      );
      res.status(200).json({
        message: "Address updated successfully",
        success: true,
        data,
      });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Address update failed. Please try again.", error });
    }
  }
);

// 4. Opportunity Create
app.post("/api/opportunity", ensureSalesforceAccessToken, async (req, res) => {
  try {
    const data = await salesforceRequest(
      "POST",
      "sobjects/Opportunity",
      req.body
    );
    res.status(201).json({ data, success: true });
  } catch (error) {
    res.status(500).json(error);
  }
});

// 5. Opportunity Update
app.patch(
  "/api/opportunity/:id",
  ensureSalesforceAccessToken,
  async (req, res) => {
    try {
      const opportunityId = req.params.id;
      const { stageName } = req.body;
      const data = await salesforceRequest(
        "PATCH",
        `sobjects/Opportunity/${opportunityId}`,
        { StageName: stageName }
      );
      res.json(data);
    } catch (error) {
      res.status(500).json(error);
    }
  }
);

// 6. DonationSummary Create
app.post(
  "/api/donationsummary",
  ensureSalesforceAccessToken,
  async (req, res) => {
    try {
      const data = await salesforceRequest(
        "POST",
        "sobjects/DonationSummary__c",
        req.body
      );
      res.status(201).json(data);
    } catch (error) {
      res.status(500).json(error);
    }
  }
);

// 7. Internal API for refreshing access token (optional)
app.post("/internal/refresh-token", async (req, res) => {
  try {
    await refreshAccessToken();
    res.status(200).json({ message: "Access token refreshed successfully" });
  } catch (error) {
    res.status(500).json({ message: "Failed to refresh access token", error });
  }
});

// Start Server
app.listen(PORT,"0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
