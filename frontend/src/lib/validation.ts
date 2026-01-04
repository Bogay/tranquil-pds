import { err, ok, type Result } from "./types/result.ts";
import {
  type AtUri,
  type Cid,
  type Did,
  type DidPlc,
  type DidWeb,
  type EmailAddress,
  type Handle,
  isAtUri,
  isCid,
  isDid,
  isDidPlc,
  isDidWeb,
  isEmail,
  isHandle,
  isISODate,
  isNsid,
  type ISODateString,
  type Nsid,
} from "./types/branded.ts";

export class ValidationError extends Error {
  constructor(
    message: string,
    public readonly field?: string,
    public readonly value?: unknown,
  ) {
    super(message);
    this.name = "ValidationError";
  }
}

export function parseDid(s: string): Result<Did, ValidationError> {
  if (isDid(s)) {
    return ok(s);
  }
  return err(new ValidationError(`Invalid DID: ${s}`, "did", s));
}

export function parseDidPlc(s: string): Result<DidPlc, ValidationError> {
  if (isDidPlc(s)) {
    return ok(s);
  }
  return err(new ValidationError(`Invalid DID:PLC: ${s}`, "did", s));
}

export function parseDidWeb(s: string): Result<DidWeb, ValidationError> {
  if (isDidWeb(s)) {
    return ok(s);
  }
  return err(new ValidationError(`Invalid DID:WEB: ${s}`, "did", s));
}

export function parseHandle(s: string): Result<Handle, ValidationError> {
  const trimmed = s.trim().toLowerCase();
  if (isHandle(trimmed)) {
    return ok(trimmed);
  }
  return err(new ValidationError(`Invalid handle: ${s}`, "handle", s));
}

export function parseEmail(s: string): Result<EmailAddress, ValidationError> {
  const trimmed = s.trim().toLowerCase();
  if (isEmail(trimmed)) {
    return ok(trimmed);
  }
  return err(new ValidationError(`Invalid email: ${s}`, "email", s));
}

export function parseAtUri(s: string): Result<AtUri, ValidationError> {
  if (isAtUri(s)) {
    return ok(s);
  }
  return err(new ValidationError(`Invalid AT-URI: ${s}`, "uri", s));
}

export function parseCid(s: string): Result<Cid, ValidationError> {
  if (isCid(s)) {
    return ok(s);
  }
  return err(new ValidationError(`Invalid CID: ${s}`, "cid", s));
}

export function parseNsid(s: string): Result<Nsid, ValidationError> {
  if (isNsid(s)) {
    return ok(s);
  }
  return err(new ValidationError(`Invalid NSID: ${s}`, "nsid", s));
}

export function parseISODate(
  s: string,
): Result<ISODateString, ValidationError> {
  if (isISODate(s)) {
    return ok(s);
  }
  return err(new ValidationError(`Invalid ISO date: ${s}`, "date", s));
}

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  strength: "weak" | "fair" | "good" | "strong";
}

export function validatePassword(password: string): PasswordValidationResult {
  const errors: string[] = [];

  if (password.length < 8) {
    errors.push("Password must be at least 8 characters");
  }
  if (password.length > 256) {
    errors.push("Password must be at most 256 characters");
  }
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain a lowercase letter");
  }
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain an uppercase letter");
  }
  if (!/\d/.test(password)) {
    errors.push("Password must contain a number");
  }

  let strength: PasswordValidationResult["strength"] = "weak";
  if (errors.length === 0) {
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    const isLong = password.length >= 12;
    const isVeryLong = password.length >= 16;

    if (isVeryLong && hasSpecial) {
      strength = "strong";
    } else if (isLong || hasSpecial) {
      strength = "good";
    } else {
      strength = "fair";
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    strength,
  };
}

export function validateHandle(
  handle: string,
): Result<Handle, ValidationError> {
  const trimmed = handle.trim().toLowerCase();

  if (trimmed.length < 3) {
    return err(
      new ValidationError(
        "Handle must be at least 3 characters",
        "handle",
        handle,
      ),
    );
  }

  if (trimmed.length > 253) {
    return err(
      new ValidationError(
        "Handle must be at most 253 characters",
        "handle",
        handle,
      ),
    );
  }

  if (!isHandle(trimmed)) {
    return err(new ValidationError("Invalid handle format", "handle", handle));
  }

  return ok(trimmed);
}

export function validateInviteCode(
  code: string,
): Result<string, ValidationError> {
  const trimmed = code.trim();

  if (trimmed.length === 0) {
    return err(
      new ValidationError("Invite code is required", "inviteCode", code),
    );
  }

  const pattern = /^[a-zA-Z0-9-]+$/;
  if (!pattern.test(trimmed)) {
    return err(
      new ValidationError("Invalid invite code format", "inviteCode", code),
    );
  }

  return ok(trimmed);
}

export function validateTotpCode(
  code: string,
): Result<string, ValidationError> {
  const trimmed = code.trim().replace(/\s/g, "");

  if (!/^\d{6}$/.test(trimmed)) {
    return err(new ValidationError("TOTP code must be 6 digits", "code", code));
  }

  return ok(trimmed);
}

export function validateBackupCode(
  code: string,
): Result<string, ValidationError> {
  const trimmed = code.trim().replace(/\s/g, "").toLowerCase();

  if (!/^[a-z0-9]{8}$/.test(trimmed)) {
    return err(new ValidationError("Invalid backup code format", "code", code));
  }

  return ok(trimmed);
}

export interface FormValidation<T> {
  validate: () => Result<T, ValidationError[]>;
  field: <K extends keyof T>(
    key: K,
    validator: (value: unknown) => Result<T[K], ValidationError>,
  ) => FormValidation<T>;
  optional: <K extends keyof T>(
    key: K,
    validator: (value: unknown) => Result<T[K], ValidationError>,
  ) => FormValidation<T>;
}

export function createFormValidation<T extends Record<string, unknown>>(
  data: Record<string, unknown>,
): FormValidation<T> {
  const validators: Array<{
    key: string;
    validator: (value: unknown) => Result<unknown, ValidationError>;
    optional: boolean;
  }> = [];

  const builder: FormValidation<T> = {
    field: (key, validator) => {
      validators.push({ key: key as string, validator, optional: false });
      return builder;
    },
    optional: (key, validator) => {
      validators.push({ key: key as string, validator, optional: true });
      return builder;
    },
    validate: () => {
      const errors: ValidationError[] = [];
      const result: Record<string, unknown> = {};

      for (const { key, validator, optional } of validators) {
        const value = data[key];

        if (value == null || value === "") {
          if (!optional) {
            errors.push(new ValidationError(`${key} is required`, key));
          }
          continue;
        }

        const validated = validator(value);
        if (validated.ok) {
          result[key] = validated.value;
        } else {
          errors.push(validated.error);
        }
      }

      if (errors.length > 0) {
        return err(errors);
      }

      return ok(result as T);
    },
  };

  return builder;
}
