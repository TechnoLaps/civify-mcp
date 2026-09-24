/** Canonical backend ResumeData shape. Keep in sync with dto/resume/ResumeData.java. */
export const RESUME_SCHEMA = {
    type: "object",
    description: "Civify ResumeData extracted by you or returned by Civify. Preserve all real details; never invent achievements. Use personalInfo for contact/summary and sections[].items for experience, education and skills. No parse call is required when you have this data.",
    properties: {
        personalInfo: {
            type: "object",
            properties: Object.fromEntries(["fullName", "email", "phone", "address", "city", "country", "summary", "jobTitle", "linkedin", "website", "github"].map(key => [key, { type: ["string", "null"] }])),
        },
        sections: {
            type: "array",
            items: {
                type: "object",
                properties: {
                    id: { type: "string" }, title: { type: "string" }, type: { type: "string", description: "experience, education, skills, or custom" },
                    visible: { type: "boolean" }, order: { type: "integer" },
                    items: {
                        type: "array", items: {
                            type: "object", properties: {
                                id: { type: ["string", "null"] }, title: { type: ["string", "null"] }, subtitle: { type: ["string", "null"] }, date: { type: ["string", "null"] },
                                description: { type: ["string", "null"] }, location: { type: ["string", "null"] }, tags: { type: "array", items: { type: "string" } }, visible: { type: "boolean" },
                            },
                        },
                    },
                },
                required: ["type", "items"],
            },
        },
        metadata: { type: "object", description: "Optional renderer settings, such as templateId and primaryColor." },
    },
    required: ["personalInfo", "sections"],
};
export const PDF_OPTIONS = {
    template: { type: "string", enum: ["modern", "classic", "creative", "executive", "minimal", "ats"], default: "modern", description: "PDF layout." },
    color: { type: "string", pattern: "^#[0-9a-fA-F]{6}$", default: "#000000", description: "PDF accent color in six-digit hex." },
};
