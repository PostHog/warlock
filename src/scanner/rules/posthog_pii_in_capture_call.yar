// Detects PII passed to posthog.capture() or posthog.identify().
//
// FP avoidance: only matches top-level keys in the first `{ ... }` object,
// so `$set: { email: ... }` (canonical PostHog person-property pattern)
// doesn't match.
//
// Known FN: top-level PII alongside `$set` in the same call – e.g.
// `.capture('e', { $set: { x: 1 }, email })` – won't match. Uncommon
// (structurally redundant); accepted tradeoff.

rule posthog_pii_in_capture_call
{
    meta:
        description = "Personally identifiable information (email, phone, SSN, address, or similar) passed to a PostHog tracking call."
        remediation = "Remove PII from event properties. Use posthog.identify() or person properties instead – https://posthog.com/docs/product-analytics/person-properties"
        severity = "high"
        category = "posthog_pii"
        action = "revert"

    strings:
        // posthog.capture() – all PII fields are a problem here
        $capture_email             = /\.capture\s*\([^{]*\{[^{}]*\b(email_address|emailAddress|emailAddr|email)\b['"]?\s*[:=]/i
        $capture_phone             = /\.capture\s*\([^{]*\{[^{}]*\b(phone_number|phoneNumber|phoneNum|phoneNo|phone|mobile_number|mobileNumber|mobile|telephone)\b['"]?\s*[:=]/i
        $capture_name_full         = /\.capture\s*\([^{]*\{[^{}]*\b(full_name|fullName|legal_name|legalName)\b['"]?\s*[:=]/i
        $capture_name_first        = /\.capture\s*\([^{]*\{[^{}]*\b(first_name|firstName|fname)\b['"]?\s*[:=]/i
        $capture_name_last         = /\.capture\s*\([^{]*\{[^{}]*\b(last_name|lastName|family_name|familyName|surname|lname)\b['"]?\s*[:=]/i
        $capture_address           = /\.capture\s*\([^{]*\{[^{}]*\b(street_address|streetAddress|home_address|homeAddress|billing_address|billingAddress|mailing_address|mailingAddress)\b['"]?\s*[:=]/i
        $capture_ssn               = /\.capture\s*\([^{]*\{[^{}]*\b(social_security_number|socialSecurityNumber|social_security|socialSecurity|ssn)\b['"]?\s*[:=]/i
        $capture_dob               = /\.capture\s*\([^{]*\{[^{}]*\b(date_of_birth|dateOfBirth|birth_date|birthDate|birthday|dob)\b['"]?\s*[:=]/i
        $capture_credit_card       = /\.capture\s*\([^{]*\{[^{}]*\b(credit_card|creditCard|card_number|cardNumber|cc_number|ccNumber|cvv|cvc)\b['"]?\s*[:=]/i
        $capture_ip                = /\.capture\s*\([^{]*\{[^{}]*\$ip\b['"]?\s*[:=]/
        $capture_passport          = /\.capture\s*\([^{]*\{[^{}]*\b(passport_number|passportNumber|passport)\b['"]?\s*[:=]/i
        $capture_drivers_license   = /\.capture\s*\([^{]*\{[^{}]*\b(drivers_license|driversLicense|driver_license|driverLicense|license_number|licenseNumber|dl_number|dlNumber)\b['"]?\s*[:=]/i
        $capture_bank_account      = /\.capture\s*\([^{]*\{[^{}]*\b(bank_account|bankAccount|account_number|accountNumber|routing_number|routingNumber|iban)\b['"]?\s*[:=]/i
        $capture_medical           = /\.capture\s*\([^{]*\{[^{}]*\b(medical_record|medicalRecord|health_record|healthRecord|patient_id|patientId|mrn)\b['"]?\s*[:=]/i
        $capture_gov_id            = /\.capture\s*\([^{]*\{[^{}]*\b(national_id|nationalId|tax_id|taxId|citizen_id|citizenId)\b['"]?\s*[:=]/i

        // posthog.identify() – exclude email/names (standard identifying fields); match sensitive PII
        $identify_ssn              = /\.identify\s*\([^{]*\{[^{}]*\b(social_security_number|socialSecurityNumber|social_security|socialSecurity|ssn)\b['"]?\s*[:=]/i
        $identify_dob              = /\.identify\s*\([^{]*\{[^{}]*\b(date_of_birth|dateOfBirth|birth_date|birthDate|birthday|dob)\b['"]?\s*[:=]/i
        $identify_credit_card      = /\.identify\s*\([^{]*\{[^{}]*\b(credit_card|creditCard|card_number|cardNumber|cc_number|ccNumber|cvv|cvc)\b['"]?\s*[:=]/i
        $identify_address          = /\.identify\s*\([^{]*\{[^{}]*\b(street_address|streetAddress|home_address|homeAddress|billing_address|billingAddress|mailing_address|mailingAddress)\b['"]?\s*[:=]/i
        $identify_passport         = /\.identify\s*\([^{]*\{[^{}]*\b(passport_number|passportNumber|passport)\b['"]?\s*[:=]/i
        $identify_drivers_license  = /\.identify\s*\([^{]*\{[^{}]*\b(drivers_license|driversLicense|driver_license|driverLicense|license_number|licenseNumber|dl_number|dlNumber)\b['"]?\s*[:=]/i
        $identify_bank_account     = /\.identify\s*\([^{]*\{[^{}]*\b(bank_account|bankAccount|account_number|accountNumber|routing_number|routingNumber|iban)\b['"]?\s*[:=]/i
        $identify_medical          = /\.identify\s*\([^{]*\{[^{}]*\b(medical_record|medicalRecord|health_record|healthRecord|patient_id|patientId|mrn)\b['"]?\s*[:=]/i
        $identify_gov_id           = /\.identify\s*\([^{]*\{[^{}]*\b(national_id|nationalId|tax_id|taxId|citizen_id|citizenId)\b['"]?\s*[:=]/i
        $identify_ip               = /\.identify\s*\([^{]*\{[^{}]*\$ip\b['"]?\s*[:=]/

    condition:
        any of them
}
