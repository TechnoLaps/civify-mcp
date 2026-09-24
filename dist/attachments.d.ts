import axios from "axios";
import https from "node:https";
export declare const MAX_DOCUMENT_BYTES: number;
export declare const FILE_SCHEMA: {
    type: string;
    description: string;
    properties: {
        download_url: {
            type: string;
        };
        file_id: {
            type: string;
        };
        mime_type: {
            type: string;
        };
        file_name: {
            type: string;
        };
    };
    required: string[];
    additionalProperties: boolean;
};
export declare function isPublicAddress(address: string): boolean;
export declare function attachmentUrl(value: string): URL;
export declare const publicLookup: NonNullable<https.AgentOptions["lookup"]>;
export declare function downloadAttachment(value: string, request?: typeof axios.get): Promise<Buffer>;
export declare function decodeDocument(value: string): Buffer;
export declare function documentMetadata(buffer: Buffer, filename?: string): {
    filename: string;
    contentType: string;
};
