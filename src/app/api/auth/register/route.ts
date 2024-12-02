// register endpoint
// full name, email, password, phone number
import { NextRequest, NextResponse } from "next/server";
import { z, ZodIssue } from "zod";
import { hash } from "bcrypt";

// The schema for request validation
const userSchema = z.object({
    fullname: z.string().min(1, "Full name is required"),
    email: z.string().email("Invalid email"),
    password: z.string().min(8, "Password must be at least 8 characters"),
    phoneNumber: z.string().min(10, "Phone number must be at least 10 characters"),
});

export async function POST(request: NextRequest) {
    try{
        const body = await request.json();

        // Validate the request body against the schema
        const result = userSchema.safeParse(body);

        if (!result.success){
            // Extract and return validation errors
            const errors = result.error.errors.map((err: ZodIssue) => ({
                field: err.path[0],
                message: err.message,
            }));
            return NextResponse.json({ errors }, { status: 400 });
        }
        const { fullname, email, password, phoneNumber } = result.data;

        // hash the password and store user data in db
        const hashedPassword = await hash(password, 10);

        return NextResponse.json({ message: "User registered successfully" }, { status: 201 });
    }
    catch (error) {
        return NextResponse.json({ message: "Error registering user" }, { status: 500 });
    }
}