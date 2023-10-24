import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterDto } from './dto/index';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcriptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwlPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-respone';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
    ) {}


  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      
      const {password, ...userData}= createUserDto;
      const newUser = new this.userModel({
        password: bcriptjs.hashSync(password,10),
        ...userData
      });

     
       await newUser.save();
       const {password:_, ...user}= newUser.toJSON();

       return user;
 
    // 1- encriptar contraseña
    // 2- guardar usuario
    // 3- generar el jwt (llave de acceso)      

    } catch (error) {
      if(error.code===11000){
        throw new BadRequestException(`${ createUserDto.email} already exist`)
      }
      throw new InternalServerErrorException('Algo esta mal')
      
    }
  }

  async register(registerDto: RegisterDto):Promise<LoginResponse>{

    const user= await this.create(registerDto);

    return {
      user: user,
      token: this.getJwtToken({id:user._id}),
      
    }
  }
  async login(loginDto: LoginDto): Promise<LoginResponse>{

    const {email,password}= loginDto;

    const user= await this.userModel.findOne({email});

    if(!user) {
       throw new UnauthorizedException('Not valid credentials -email')
    }
    if(!bcriptjs.compareSync(password,user.password)){
      throw new UnauthorizedException('Not valid credentials -password')
    }

    const {password:_ , ...rest}= user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({id:user.id}),
      
    }

  }
  async findUserById(id:string){
    const user= await this.userModel.findById(id);
    const {password, ...rest}=user.toJSON();

    return rest;
  }

  findAll(): Promise<User[]> {
    return this.userModel.find ();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwlPayload){
    const token= this.jwtService.sign(payload);
    return token;

  }
}
