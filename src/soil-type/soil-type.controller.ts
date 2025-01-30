import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  SetMetadata,
} from '@nestjs/common';
import { SoilTypeService } from './soil-type.service';
import { CreateSoilTypeDto } from './dto/create-soil-type.dto';
import { UpdateSoilTypeDto } from './dto/update-soil-type.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@ApiTags('Soil Types')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('soil-types')
export class SoilTypeController {
  constructor(private readonly soilTypeService: SoilTypeService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.soilTypeService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.soilTypeService.findOne(id);
  }

  @SetMetadata('role', 'admin')
  @Post()
  create(@Body() createSoilTypeDto: CreateSoilTypeDto) {
    return this.soilTypeService.create(createSoilTypeDto);
  }

  @SetMetadata('role', 'admin')
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateSoilTypeDto: UpdateSoilTypeDto,
  ) {
    return this.soilTypeService.update(id, updateSoilTypeDto);
  }

  @SetMetadata('role', 'admin')
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.soilTypeService.remove(id);
  }
}
