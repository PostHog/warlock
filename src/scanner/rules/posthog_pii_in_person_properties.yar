// Detects sensitive PII passed to PostHog person-property calls:
// register(), register_once(), setPersonProperties(), and
// setPersonPropertiesForFlags(). Companion to posthog_pii_in_capture_call,
// which only covers capture()/identify().
//
// Mirrors the identify() half of that rule: email and names are standard,
// expected person properties and are NOT flagged here — only sensitive,
// regulated PII is (SSN, DOB, financial, government ID, medical).
//
// FP avoidance (same as the sibling rule): only top-level keys in the first
// `{ ... }` object match, so a nested `$set: { ssn: ... }` won't.

rule posthog_pii_in_person_properties
{
    meta:
        description = "Sensitive PII (SSN, DOB, financial, government ID, or similar) passed to a PostHog person-property call (register / setPersonProperties)."
        remediation = "Remove regulated PII from person properties. Keep only non-sensitive identifying fields in PostHog – https://posthog.com/docs/product-analytics/person-properties"
        severity = "high"
        category = "posthog_pii"
        action = "remediate"
        scan_context = "output"

    strings:
        $pp_ssn             = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(social_security_number|socialSecurityNumber|social_security|socialSecurity|ssn)\b['"]?\s*[:=]/i
        $pp_dob             = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(date_of_birth|dateOfBirth|birth_date|birthDate|birthday|dob)\b['"]?\s*[:=]/i
        $pp_credit_card     = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(credit_card|creditCard|card_number|cardNumber|cc_number|ccNumber|cvv|cvc)\b['"]?\s*[:=]/i
        $pp_address         = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(street_address|streetAddress|home_address|homeAddress|billing_address|billingAddress|mailing_address|mailingAddress)\b['"]?\s*[:=]/i
        $pp_passport        = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(passport_number|passportNumber|passport)\b['"]?\s*[:=]/i
        $pp_drivers_license = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(drivers_license|driversLicense|driver_license|driverLicense|license_number|licenseNumber|dl_number|dlNumber)\b['"]?\s*[:=]/i
        $pp_bank_account    = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(bank_account|bankAccount|account_number|accountNumber|routing_number|routingNumber|iban)\b['"]?\s*[:=]/i
        $pp_medical         = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(medical_record|medicalRecord|health_record|healthRecord|patient_id|patientId|mrn)\b['"]?\s*[:=]/i
        $pp_gov_id          = /\.(register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b(national_id|nationalId|tax_id|taxId|citizen_id|citizenId)\b['"]?\s*[:=]/i

    condition:
        any of them
}
