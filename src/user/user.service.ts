import { Injectable, ConflictException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { User } from './user.schema';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async registerUser(email: string, password: string): Promise<any> {
    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({ email, password: hashedPassword });
    await newUser.save();
    return { message: 'User registered successfully' };
  }

  async loginUser(email: string, password: string): Promise<any> {
    const existingUser = await this.userModel.findOne({email});
    if (!existingUser) {
      throw new ConflictException('Email or password is incorrect!');
    }

    const isPasswordValid = await bcrypt.compare(password, existingUser.password);
    if (!isPasswordValid) {
      throw new ConflictException('Email or password is incorrect!');
    }

    console.log("Featch log in");
    return { message: 'Logged in successfully' };

  }

  async countUsers(): Promise<number> {
    return this.userModel.countDocuments();
  }
}
