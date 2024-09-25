import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthDtoSignIn {
  @IsNotEmpty()
  emailOrUsername: string;
  @IsNotEmpty()
  @IsString()
  password: string;
}

export class AuthDtoSignUp {
  @IsEmail()
  @IsNotEmpty()
  email: string;
  @IsNotEmpty()
  @IsString()
  username: string;
  @IsNotEmpty()
  @IsString()
  password: string;
}
