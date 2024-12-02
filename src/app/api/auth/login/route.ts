import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// Mock database
const users = [
  { username: 'testuser', password: bcrypt.hashSync('password123', 10) },
];

export async function POST(request: Request) {
  try {
    const { username, password } = await request.json();

    // Find the user in the mock database
    const user = users.find((u) => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return NextResponse.json({ error: 'Invalid username or password' }, { status: 401 });
    }

    // Generate JWT
    const token = jwt.sign({ username }, process.env.JWT_SECRET || 'your_secret_key', {
      expiresIn: '1h',
    });

    return NextResponse.json({ message: 'Login successful', token });
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error: 'Something went wrong' }, { status: 500 });
  }
}
