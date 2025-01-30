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
import { UnitMeasureService } from './unit-measure.service';
import { CreateUnitMeasureDto } from './dto/create-unit-measure.dto';
import { UpdateUnitMeasureDto } from './dto/update-unit-measure.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@ApiTags('Unit Measures')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('unit-measures')
export class UnitMeasureController {
  constructor(private readonly unitMeasureService: UnitMeasureService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.unitMeasureService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.unitMeasureService.findOne(id);
  }

  @SetMetadata('role', 'admin')
  @Post()
  create(@Body() createUnitMeasureDto: CreateUnitMeasureDto) {
    return this.unitMeasureService.create(createUnitMeasureDto);
  }

  @SetMetadata('role', 'admin')
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateUnitMeasureDto: UpdateUnitMeasureDto,
  ) {
    return this.unitMeasureService.update(id, updateUnitMeasureDto);
  }

  @SetMetadata('role', 'admin')
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.unitMeasureService.remove(id);
  }
}
