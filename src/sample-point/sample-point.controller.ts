import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { SamplePointService } from './sample-point.service';
import { CreateSamplePointDto } from './dto/create-sample-point.dto';
import { UpdateSamplePointDto } from './dto/update-sample-point.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('Sample Points')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('sample-points')
export class SamplePointController {
  constructor(private readonly samplePointService: SamplePointService) {}

  @Get()
  findAll() {
    return this.samplePointService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.samplePointService.findOne(id);
  }

  @Post()
  create(@Body() createSamplePointDto: CreateSamplePointDto) {
    return this.samplePointService.create(createSamplePointDto);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateSamplePointDto: UpdateSamplePointDto,
  ) {
    return this.samplePointService.update(id, updateSamplePointDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.samplePointService.remove(id);
  }
}
