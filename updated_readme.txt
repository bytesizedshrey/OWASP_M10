---

### **What Our Code Does**
Our app checks for problems in mobile app files (like APK or IPA) and tells us about possible attacks based on those problems, such as weak encryption leading to brute-force attacks.

#### **How It Analyzes Apps**
- **Static Analysis**: Looks at the app’s code and settings without running it. It checks things like permissions and weak encryption methods.
- **Dynamic Analysis**: Runs the app on a device and watches how it behaves, especially with encryption. (Note: This part isn’t fully built yet—it needs extra setup.)

#### **How It Finds Potential Attacks**
When it finds issues (like weak encryption), it matches them to five possible attacks, such as brute-force or data leaks. 
It does this by looking for simple keywords in the problems it finds and suggests risks based on them.

---

### **Static Analysis Details**
#### **Android (APK/XAPK)**
- **Manifest File**: Reads the `AndroidManifest.xml` to check permissions, like `WRITE_EXTERNAL_STORAGE`, 
    which might mean unsafe storage. It also looks for cleartext traffic (non-HTTPS) if `usesCleartextTraffic="false"` is missing, showing a risk of data being grabbed.
- **DEX Files**: Uses Androguard to find weak algorithms (like DES, MD5, SHA1, RC4) in the app’s compiled code, which aren’t safe by today’s standards.
- **Smali Files**: Breaks down the APK with apktool and scans Smali files for weak algorithms or hardcoded keys (like secret codes written directly in the app), which are risky.

#### **iOS (IPA)**
- Uses the `otool` command to check for old libraries (like an outdated OpenSSL version) that could have security problems. (Full analysis isn’t done yet—it’s basic for now.)

---

### **How We Know the Analysis is Correct**
Our analysis is trustworthy because:
- **Static Analysis**: Looks for known problems, like specific permissions or weak algorithm names, that experts agree are risky.
- **Dynamic Analysis**: Watches the app’s real behavior when running, which is more accurate, but it’s not fully ready yet—it simulates real use when set up.
- **Tools**: We use reliable tools like Androguard (for Android) and Frida (for dynamic checks), which security experts trust. Check their guides: [Androguard Docs](https://androguard.readthedocs.io/) and [Frida Docs](https://frida.re/docs/home/).
- **Validation**: Matches results against known patterns and standards that the security world follows.

---

### **How It Identifies Potential Attacks**
When the app finds problems, it suggests possible attacks based on them. It does this by checking simple keywords in the problem descriptions:
- If it sees "weak" (like weak encryption), it says: "Hackers could use brute-force attacks to crack this."
- If it sees "insecure" or "cleartext" (like unsafe internet traffic), it says: "Data could be stolen with a Man-in-the-Middle attack."
- If it sees "hardcoded" or "key" (like secret codes in the app), it says: "Hackers might pull out sensitive keys."

---

### **What is the Manifest?**
The manifest, or `AndroidManifest.xml`, is a file inside every Android app (APK or XAPK). 
It’s like an ID card for the app—it tells the Android system the app’s name, what it can do, 
and what permissions it needs. In simple terms, it’s the app saying, "This is me, and I need these powers to work."

#### **Checking the Manifest**
- **Permissions**: Looks for risky ones, like `WRITE_EXTERNAL_STORAGE`. If found, it warns, "This could let the app write stuff that might leak."

- **Cleartext Traffic**: If the app uses the internet but doesn’t force safe HTTPS (missing `usesCleartextTraffic="false"`), 
it warns, "This could let hackers grab data with a Man-in-the-Middle attack."

- **Component Safety**: Checks if app parts (like activities) are open to other apps and not secure, which could let bad apps mess with it.

---

### **What is Cleartext?**
Cleartext means data sent without protection—like plain text anyone can read if they catch it. 
For example, sending stuff over HTTP instead of HTTPS is cleartext, and it’s risky because there’s no shield. HTTPS encrypts it so only the sender and receiver understand it.

---

### **Simple Explanation (Updated)**
**APK Kaise Check Karta Hai**: APK ko Androguard se kholte hain aur DEX mein weak algorithms dekhte hain. Manifest se permissions aur settings check karte hain, aur apktool se Smali files nikal ke unme weak cheezein ya secrets dhoondhte hain.  
**IPA Kaise Check Karta Hai**: IPA ko otool se padhte hain taaki purani libraries dhoondh sakein, lekin abhi full check nahi hota—iOS alag hai. Dynamic ke liye jailbreak chahiye, jo abhi nahi hai.  
**MentorPoint**: "APK ke liye DEX, manifest, aur Smali teeno check hote hain taaki security issues milein, jaise weak encryption ya risky permissions. Results ko 5 attack scenarios se match karte hain taaki risks samajh aayein."

---

### **Why MobSF Isn’t Always Better**
MobSF is a good all-in-one tool, but Frida and Androguard are experts in their areas. For our app, MobSF could help with iOS and more checks, but keeping Frida for dynamic analysis and Androguard for Android depth makes our tool special. Mixing MobSF with these could make it even better—easy to use and super strong.

---

### **How Attack Scenarios Work (Updated)**
- **Scenario #1 (MitM)**: Shows up if "cleartext" or "insecure" is found (e.g., unsafe internet traffic from manifest).
- **Scenario #2 (Brute-Force)**: Shows up if "weak" is found (e.g., weak algorithms in DEX or Smali).
- **Scenario #3 (Downgrade)**: Shows up if "weak" or "insecure" is found (e.g., weak algorithms or settings).
- **Scenario #4 (Key Management)**: Shows up if "hardcoded" or "key" is found (e.g., keys in Smali).
- **Scenario #5 (Implementation Flaws)**: Shows up if "weak", "insecure", or "error" is found (e.g., DEX errors or weak settings).

---

### **Updated**
"Our code now checks three parts of an APK: DEX, manifest, and Smali. 
We use Androguard to find weak algorithms in DEX, 
look at permissions and settings in the manifest, 
and use apktool to scan Smali files for weak stuff or hidden keys. 
Then, it matches these problems to five attack scenarios—like Man-in-the-Middle or Brute-Force—to show what could go wrong. It looks for keywords like 'weak' or 'cleartext' to pick the right risks."

#### **Why It Works**
- **Easy Words**: Uses "checks," "finds," "matches," and "shows" to keep it simple.
- **Clear Steps**: Covers DEX, manifest, Smali, and how risks are shown.
- **Natural**: Short and easy to say for your presentation.

For iOS IPA files, our app now does more than before. 
It opens the IPA, checks the settings file for unsafe network rules, looks at permissions for risky stuff like debugging, 
and scans the app’s code with otool to find old libraries or weak encryption.
It also stops crashes on big files by checking their size first. 
This makes it better at finding iOS problems and showing risks like Man-in-the-Middle attacks

For IPA files, there’s no direct DEX or Smali equivalent (since iOS uses Mach-O binaries), and the manifest-like file is Info.plist. 
We’ll adapt the IPA analysis to mirror these checks as closely as possible:

            Binary (Mach-O): Check for weak algorithms (like DEX/Smali).
            Info.plist: Check for risky settings and network issues (like manifest).
            Hardcoded Keys: Look in the binary (like Smali).


1.manifest.xml (access and understand manually)
2.top10 apps of top5 categories
3."Am I Vulnerable To ‘Insufficient Cryptography" find which can be done by static and which can be done dynamically (choose any1 to perform statiic analysis)
