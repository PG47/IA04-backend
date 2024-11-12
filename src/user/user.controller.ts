import { Controller, Post, Body, BadRequestException, HttpStatus, Get, UseGuards, Request, ConflictException, UnauthorizedException, Res } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Response } from 'express';

@Controller('user')
export class UserController {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  @Post('register')
  async register(@Body() body, @Res() res: Response) {
    const { email, password } = body;
    if (!email || !password) {
      throw new BadRequestException('Email and password cannot be empty');
    }
    try {
      const result = await this.userService.registerUser(email, password);
      return res.status(HttpStatus.CREATED).json(result); 
    } catch (error) {
      throw new ConflictException(error.message || 'Error registering user');
    }
  }

  @Post('login')
  async login(@Body() body) {
    const { email, password } = body;
    
    if (!email || !password) {
      throw new BadRequestException('Email and password cannot be empty');
    }

    try {
      const result = await this.userService.loginUser(email, password);
      return result; // Pass the entire result with message, accessToken, and user details
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException('Email or password is incorrect!');
    }
  }


  @Get('count')
  async getUserCount(@Request() req) {
    try {
      const count = await this.userService.countUsers();
      return { count };
    } catch (error) {
      throw new ConflictException('Error fetching user count');
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    const user = req.user; 
    console.log('User profile:', user);
    return { email: user.email, id: user.sub }; 
  }
}
