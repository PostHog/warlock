// Detects personally identifiable information (PII) passed to
// posthog.capture(), posthog.identify(), or the $set property object.
//
// Pattern approach:
//   - Match `.capture(`, `.identify(`, or `$set` contexts
//   - Bound distance between the function/object opener and the field name to
//     200 characters so patterns don't sprawl across unrelated code
//   - Require word boundaries (\b) around field names so `email_verified` and
//     `phone_call_duration` (prefixes of PII field names, but not PII
//     themselves) don't match
//   - Require a separator (`:` or `=`, optionally preceded by a closing
//     quote for JSON/Python/YAML) so the field name is in key position, not
//     incidental text

rule posthog_pii_in_capture_call
{
    meta:
        description = "Personally identifiable information (email, phone, SSN, address, or similar) passed to a PostHog tracking call."
        remediation = "Remove the PII from the event properties. If you need to attribute an event to a user, use posthog.identify() with a stable userId — don't send the raw PII values themselves."
        severity = "high"
        category = "posthog_pii"
        action = "revert"

    strings:
        // posthog.capture() — all PII fields are a problem here
        $capture_email             = /\.capture\s*\([^)]{0,200}\b(email_address|emailAddress|emailAddr|email)\b['"]?\s*[:=]/i
        $capture_phone             = /\.capture\s*\([^)]{0,200}\b(phone_number|phoneNumber|phoneNum|phoneNo|phone|mobile_number|mobileNumber|mobile|telephone)\b['"]?\s*[:=]/i
        $capture_name_full         = /\.capture\s*\([^)]{0,200}\b(full_name|fullName|legal_name|legalName)\b['"]?\s*[:=]/i
        $capture_name_first        = /\.capture\s*\([^)]{0,200}\b(first_name|firstName|fname)\b['"]?\s*[:=]/i
        $capture_name_last         = /\.capture\s*\([^)]{0,200}\b(last_name|lastName|family_name|familyName|surname|lname)\b['"]?\s*[:=]/i
        $capture_address           = /\.capture\s*\([^)]{0,200}\b(street_address|streetAddress|home_address|homeAddress|billing_address|billingAddress|mailing_address|mailingAddress)\b['"]?\s*[:=]/i
        $capture_ssn               = /\.capture\s*\([^)]{0,200}\b(social_security_number|socialSecurityNumber|social_security|socialSecurity|ssn)\b['"]?\s*[:=]/i
        $capture_dob               = /\.capture\s*\([^)]{0,200}\b(date_of_birth|dateOfBirth|birth_date|birthDate|birthday|dob)\b['"]?\s*[:=]/i
        $capture_credit_card       = /\.capture\s*\([^)]{0,200}\b(credit_card|creditCard|card_number|cardNumber|cc_number|ccNumber|cvv|cvc)\b['"]?\s*[:=]/i
        $capture_ip                = /\.capture\s*\([^)]{0,200}\$ip\b['"]?\s*[:=]/
        $capture_passport          = /\.capture\s*\([^)]{0,200}\b(passport_number|passportNumber|passport)\b['"]?\s*[:=]/i
        $capture_drivers_license   = /\.capture\s*\([^)]{0,200}\b(drivers_license|driversLicense|driver_license|driverLicense|license_number|licenseNumber|dl_number|dlNumber)\b['"]?\s*[:=]/i
        $capture_bank_account      = /\.capture\s*\([^)]{0,200}\b(bank_account|bankAccount|account_number|accountNumber|routing_number|routingNumber|iban)\b['"]?\s*[:=]/i
        $capture_medical           = /\.capture\s*\([^)]{0,200}\b(medical_record|medicalRecord|health_record|healthRecord|patient_id|patientId|mrn)\b['"]?\s*[:=]/i
        $capture_gov_id            = /\.capture\s*\([^)]{0,200}\b(national_id|nationalId|tax_id|taxId|citizen_id|citizenId)\b['"]?\s*[:=]/i

        // posthog.identify() — exclude email/names (standard identifying fields); match sensitive PII
        $identify_ssn              = /\.identify\s*\([^)]{0,200}\b(social_security_number|socialSecurityNumber|social_security|socialSecurity|ssn)\b['"]?\s*[:=]/i
        $identify_dob              = /\.identify\s*\([^)]{0,200}\b(date_of_birth|dateOfBirth|birth_date|birthDate|birthday|dob)\b['"]?\s*[:=]/i
        $identify_credit_card      = /\.identify\s*\([^)]{0,200}\b(credit_card|creditCard|card_number|cardNumber|cc_number|ccNumber|cvv|cvc)\b['"]?\s*[:=]/i
        $identify_address          = /\.identify\s*\([^)]{0,200}\b(street_address|streetAddress|home_address|homeAddress|billing_address|billingAddress|mailing_address|mailingAddress)\b['"]?\s*[:=]/i
        $identify_passport         = /\.identify\s*\([^)]{0,200}\b(passport_number|passportNumber|passport)\b['"]?\s*[:=]/i
        $identify_drivers_license  = /\.identify\s*\([^)]{0,200}\b(drivers_license|driversLicense|driver_license|driverLicense|license_number|licenseNumber|dl_number|dlNumber)\b['"]?\s*[:=]/i
        $identify_bank_account     = /\.identify\s*\([^)]{0,200}\b(bank_account|bankAccount|account_number|accountNumber|routing_number|routingNumber|iban)\b['"]?\s*[:=]/i
        $identify_medical          = /\.identify\s*\([^)]{0,200}\b(medical_record|medicalRecord|health_record|healthRecord|patient_id|patientId|mrn)\b['"]?\s*[:=]/i
        $identify_gov_id           = /\.identify\s*\([^)]{0,200}\b(national_id|nationalId|tax_id|taxId|citizen_id|citizenId)\b['"]?\s*[:=]/i
        $identify_ip               = /\.identify\s*\([^)]{0,200}\$ip\b['"]?\s*[:=]/

        // $set property object — posthog's user-property-setting shorthand
        $set_email                 = /\$set\s*[{(][^}]{0,200}\b(email_address|emailAddress|emailAddr|email)\b['"]?\s*[:=]/i
        $set_phone                 = /\$set\s*[{(][^}]{0,200}\b(phone_number|phoneNumber|phoneNum|phoneNo|phone|mobile_number|mobileNumber|mobile|telephone)\b['"]?\s*[:=]/i

    condition:
        any of them
}
