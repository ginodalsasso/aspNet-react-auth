import type { ChangeEvent } from "react";

interface HoneypotFieldProps {
    value: string; // value of the honeypot field
    onChange: (e: ChangeEvent<HTMLInputElement>) => void; // handleChange function
}

export default function HoneypotField({ value, onChange }: HoneypotFieldProps) {
    return (
        <div aria-hidden="true" style={{ position: 'absolute', left: '-9999px' }}>
            <label htmlFor="website">Leave this field empty</label>
            <input
                type="text"
                id="website"
                name="website"
                value={value}
                onChange={onChange}
                autoComplete="off"
                tabIndex={-1}
            />
        </div>
    );
}
