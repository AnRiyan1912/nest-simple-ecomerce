import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator';
import { AuthDtoSignIn, AuthDtoSignUp } from 'src/dto/auth/auth.dto';
import { Tokens } from './types';

@Controller('api/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('/signIn')
  @HttpCode(HttpStatus.OK)
  signIn(@Body() request: AuthDtoSignIn) {
    return this.authService.signIn(request);
  }

  @Public()
  @Post('/signUp')
  @HttpCode(HttpStatus.CREATED)
  signUp(@Body() request: AuthDtoSignUp): Promise<Tokens> {
    return this.authService.signUp(request);
  }

  @Public()
  @Post('/verify-otp')
  @HttpCode(HttpStatus.OK)
  verifyEmailOtp(@Query('token') token: string, @Query('otp') otp: string) {
    return this.authService.verifyOtpCode(token, otp);
  }
}
