/** Canonical backend ResumeData shape. Keep in sync with dto/resume/ResumeData.java. */
export declare const RESUME_SCHEMA: {
    readonly type: "object";
    readonly description: "Civify ResumeData extracted by you or returned by Civify. Preserve all real details; never invent achievements. Use personalInfo for contact/summary and sections[].items for experience, education and skills. No parse call is required when you have this data.";
    readonly properties: {
        readonly personalInfo: {
            readonly type: "object";
            readonly properties: {
                [k: string]: {
                    type: string[];
                };
            };
        };
        readonly sections: {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly title: {
                        readonly type: "string";
                    };
                    readonly type: {
                        readonly type: "string";
                        readonly description: "experience, education, skills, or custom";
                    };
                    readonly visible: {
                        readonly type: "boolean";
                    };
                    readonly order: {
                        readonly type: "integer";
                    };
                    readonly items: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                            readonly properties: {
                                readonly id: {
                                    readonly type: readonly ["string", "null"];
                                };
                                readonly title: {
                                    readonly type: readonly ["string", "null"];
                                };
                                readonly subtitle: {
                                    readonly type: readonly ["string", "null"];
                                };
                                readonly date: {
                                    readonly type: readonly ["string", "null"];
                                };
                                readonly description: {
                                    readonly type: readonly ["string", "null"];
                                };
                                readonly location: {
                                    readonly type: readonly ["string", "null"];
                                };
                                readonly tags: {
                                    readonly type: "array";
                                    readonly items: {
                                        readonly type: "string";
                                    };
                                };
                                readonly visible: {
                                    readonly type: "boolean";
                                };
                            };
                        };
                    };
                };
                readonly required: readonly ["type", "items"];
            };
        };
        readonly metadata: {
            readonly type: "object";
            readonly description: "Optional renderer settings, such as templateId and primaryColor.";
        };
    };
    readonly required: readonly ["personalInfo", "sections"];
};
export declare const PDF_OPTIONS: {
    template: {
        type: string;
        enum: string[];
        default: string;
        description: string;
    };
    color: {
        type: string;
        pattern: string;
        default: string;
        description: string;
    };
};
