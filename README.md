# CVSS v3.1 Risk Calculator - Student Guide

## What is CVSS? (The Basics)

**CVSS** stands for **Common Vulnerability Scoring System**. Think of it like this:

- When you find a bug in software that hackers could use, how do you know if it's super dangerous or just a small problem?
- CVSS gives every security bug a score from **0 to 10**
- **0 = Harmless** | **10 = Extremely dangerous, fix immediately!**

It's like giving grades to security problems so everyone around the world uses the same scoring system.

## Why Do We Need CVSS?

**The Problem:** 
- Company A finds a bug and says "This is terrible!"
- Company B finds the same bug and says "Meh, not that bad"
- Company C doesn't know who to believe

**The Solution:**
- CVSS gives both companies the same score (let's say 7.5)
- Now everyone knows it's "High" severity
- No more confusion!

## How Does CVSS Work? (The Big Picture)

CVSS asks you **8 simple questions** about a security bug:

### Part 1: How easy is it to attack? (4 questions)
1. **Where can the hacker attack from?** (Attack Vector)
2. **Is it easy or hard to do?** (Attack Complexity)
3. **Does the hacker need a username/password?** (Privileges Required)
4. **Does someone need to click something?** (User Interaction)

### Part 2: How much damage can be done? (4 questions)
5. **Can it affect other systems too?** (Scope)
6. **Can the hacker steal secret information?** (Confidentiality)
7. **Can the hacker change or delete things?** (Integrity) 
8. **Can the hacker make the system stop working?** (Availability)

Then CVSS does some math with your answers and gives you a final score!

## The Questions Explained (In Simple Terms)

### Question 1: Attack Vector (AV) - "Where can the hacker attack from?"

**Think of it like your house:**

- 🌐 **Network (Most dangerous)** = Hacker can attack from anywhere on the internet
  - Like: Someone can break into your house from anywhere in the world
  - **Score value: 0.85**

- 🏠 **Adjacent** = Hacker needs to be on the same network (like same WiFi)
  - Like: Someone needs to be in your neighborhood to break in
  - **Score value: 0.62**

- 🖥️ **Local** = Hacker needs to already be on the same computer
  - Like: Someone needs to already be inside your house to steal stuff
  - **Score value: 0.55**

- 🔒 **Physical (Least dangerous)** = Hacker needs to physically touch the computer
  - Like: Someone needs to physically break down your door
  - **Score value: 0.20**

### Question 2: Attack Complexity (AC) - "Is it easy or hard to do?"

- 😈 **Low (More dangerous)** = Easy to do, works most of the time
  - Like: Your door is always unlocked
  - **Score value: 0.77**

- 🤔 **High (Less dangerous)** = Hard to do, needs perfect conditions
  - Like: Need to pick 3 different locks at exactly midnight
  - **Score value: 0.44**

### Question 3: Privileges Required (PR) - "Does the hacker need login?"

- 👿 **None (Most dangerous)** = No username/password needed
  - Like: Your house has no locks at all
  - **Score value: 0.85**

- 😐 **Low** = Needs basic user account (like any employee login)
  - Like: Need a basic key that many people have
  - **Score value: 0.62 or 0.68** (depends on Scope)

- 🛡️ **High (Least dangerous)** = Needs admin/boss level access
  - Like: Need the master key that only the owner has
  - **Score value: 0.27 or 0.50** (depends on Scope)

### Question 4: User Interaction (UI) - "Does someone need to click something?"

- 🤖 **None (More dangerous)** = Attack happens automatically
  - Like: Burglar breaks in while you're sleeping
  - **Score value: 0.85**

- 👆 **Required (Less dangerous)** = Someone must click a link, open a file, etc.
  - Like: You have to open the door for the burglar yourself
  - **Score value: 0.62**

### Question 5: Scope (S) - "Can it affect other systems too?"

- 📦 **Unchanged** = Attack only affects one system
  - Like: Burglar can only rob your house
  
- 🏘️ **Changed** = Attack can spread to other connected systems  
  - Like: Burglar can rob your house AND your neighbor's house

### Question 6: Confidentiality (C) - "Can the hacker see secret stuff?"

- 🚫 **None** = Cannot see any secrets (**Value: 0.00**)
- 👀 **Low** = Can see some secrets (**Value: 0.22**)
- 😱 **High** = Can see ALL secrets (**Value: 0.56**)

### Question 7: Integrity (I) - "Can the hacker change or delete things?"

- 🚫 **None** = Cannot change anything (**Value: 0.00**)
- ✏️ **Low** = Can change some things (**Value: 0.22**)
- 💀 **High** = Can change/delete everything (**Value: 0.56**)

### Question 8: Availability (A) - "Can the hacker break the system?"

- 🚫 **None** = System keeps working fine (**Value: 0.00**)
- 🐌 **Low** = System becomes slow or partially broken (**Value: 0.22**)
- 💥 **High** = System completely stops working (**Value: 0.56**)

## The Math Behind CVSS (Formulas Explained)

Don't worry - the calculator does all this math for you! But here's how it works:

### Step 1: Calculate Exploitability Score

**Formula:**
```
Exploitability = 8.22 × Attack_Vector × Attack_Complexity × Privileges_Required × User_Interaction
```

**Example:** Network + Low complexity + Low privileges + No user interaction
```
Exploitability = 8.22 × 0.85 × 0.77 × 0.62 × 0.85 = 2.84
```

**What this means:** Higher number = easier to exploit

### Step 2: Calculate Impact Score

**First, calculate ISS (Impact Sub Score):**
```
ISS = 1 - [(1 - Confidentiality) × (1 - Integrity) × (1 - Availability)]
```

**Example:** High confidentiality + No integrity + No availability
```
ISS = 1 - [(1 - 0.56) × (1 - 0.00) × (1 - 0.00)]
ISS = 1 - [0.44 × 1.00 × 1.00] = 1 - 0.44 = 0.56
```

**Then calculate Impact:**
- **If Scope = Unchanged:** `Impact = 6.42 × ISS`
- **If Scope = Changed:** `Impact = 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15`

**Example with Unchanged Scope:**
```
Impact = 6.42 × 0.56 = 3.60
```

**What this means:** Higher number = more damage possible

### Step 3: Calculate Final Base Score

**Formula:**
```
If Impact ≤ 0: Base Score = 0

If Scope = Unchanged: Base Score = min(Impact + Exploitability, 10.0)
If Scope = Changed: Base Score = min(1.08 × (Impact + Exploitability), 10.0)
```

**Example:**
```
Base Score = min(3.60 + 2.84, 10.0) = min(6.44, 10.0) = 6.44
```

**Special Rounding Rule:** Always round UP to 1 decimal place
```
6.44 becomes 6.5 (not 6.4)
```

## Understanding Your Results

### The Three Numbers You Get:

1. **Exploitability Score (0-10)** = How easy is it for hackers to use this bug?
2. **Impact Score (0-10)** = How much damage can they do with it?  
3. **Base Score (0-10)** = The final grade combining both

### The Color System (Like Traffic Lights):

- 🔴 **Red (9.0-10.0) = Critical** → "Drop everything and fix this NOW!"
- 🟠 **Orange (7.0-8.9) = High** → "Fix this very soon"
- 🟡 **Yellow (4.0-6.9) = Medium** → "Fix this when you can"
- 🟢 **Green (0.1-3.9) = Low** → "Fix this eventually"  
- ⚪ **Gray (0.0) = None** → "Not actually dangerous"

## Real Example: The MySQL Bug

Let's score a real security problem step by step:

**The Problem:** A bug in MySQL database software that lets hackers read (but not change) any data if they have a basic login.

**Our Answers:**
- Attack Vector: **Network** (can attack from internet) = 0.85
- Attack Complexity: **Low** (easy to do) = 0.77
- Privileges Required: **Low** (need basic login) = 0.62
- User Interaction: **None** (works automatically) = 0.85
- Scope: **Unchanged** (only affects the database)
- Confidentiality: **High** (can read all data) = 0.56
- Integrity: **None** (cannot change data) = 0.00
- Availability: **None** (system keeps working) = 0.00

**Step 1 - Exploitability:**
```
Exploitability = 8.22 × 0.85 × 0.77 × 0.62 × 0.85 = 2.84
```

**Step 2 - Impact:**
```
ISS = 1 - (1-0.56) × (1-0.00) × (1-0.00) = 1 - 0.44 = 0.56
Impact = 6.42 × 0.56 = 3.60
```

**Step 3 - Base Score:**
```
Base Score = min(2.84 + 3.60, 10.0) = 6.44 → rounds up to 6.5
```

**Final Result:** 6.5 = **Medium Severity (Yellow)**

**What this means:** "This is moderately dangerous. It should be fixed, but it's not an emergency because hackers need a login first and they can't break anything - just read data."

## How to Use This Calculator

### For Students:
1. **Try the MySQL example** - Click the "Load MySQL Scenario" button to see how it works
2. **Change one thing at a time** - See how each choice affects the final score
3. **Play with extremes** - Try making everything "High" vs everything "None"
4. **Ask "what if" questions** - What if no login was needed? What if they could delete data?

### Practice Questions:
- What would happen to the score if the MySQL bug didn't need any login?
- What if hackers could delete data instead of just reading it?
- What if the bug only worked when someone clicked a malicious link?

## Why These Numbers Matter in Real Life

### For Companies:
- **Critical (9-10):** CEO gets woken up at 3 AM
- **High (7-8.9):** Security team works weekend  
- **Medium (4-6.9):** Fixed in next monthly update
- **Low (0.1-3.9):** Fixed when convenient

### For You as a Student:
- Learn to think like a security professional
- Understand how to prioritize problems
- See how small changes can make big differences in risk
- Practice with real-world scenarios

## Common Mistakes Students Make

1. **"High impact = High score"** → Wrong! If it's super hard to exploit, the score stays low
2. **"Easy to exploit = High score"** → Wrong! If it doesn't do much damage, score stays low
3. **"Rounding down"** → Wrong! CVSS always rounds UP (6.44 becomes 6.5, not 6.4)
4. **"Guessing the math"** → The formulas are precise - use the calculator!

## Key Takeaways for Students

### The Big Ideas:
- **Risk = Likelihood × Impact** (How easy to exploit × How much damage)
- **Context matters** (A "High" score bug might not matter if you don't use that software)
- **Standardization is powerful** (Everyone using the same system prevents confusion)
- **Small changes matter** (Requiring a login can drop a score significantly)

### Skills You're Learning:
- **Risk assessment** - How dangerous is this really?
- **Prioritization** - What should we fix first?
- **Communication** - How do we explain risk to non-technical people?
- **Critical thinking** - What assumptions are we making?

## Practice With the Calculator

### Easy Exercise:
Load the MySQL scenario and try changing:
- What if no login was required? (Change PR to "None")
- What if hackers could also delete data? (Change Availability to "High")
- What if it only worked on the local network? (Change AV to "Adjacent")

### Challenge Exercise:
Create your own scenario:
- A bug in a mobile app that steals contacts when you open a malicious link
- A website bug that lets anyone see other users' private messages  
- A smart home device that can be controlled by neighbors on the same WiFi

**Remember:** There's no "right" or "wrong" scores - only accurate scores based on the facts you know about the vulnerability!

---

**Ready to start?** Open the calculator and click "Load MySQL Scenario" to see your first real vulnerability score! 🎯
