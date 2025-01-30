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
import { PixelSampleService } from './pixel-sample.service';
import { CreatePixelSampleDto } from './dto/create-pixel-sample.dto';
import { UpdatePixelSampleDto } from './dto/update-pixel-sample.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('Pixel Samples')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('pixel-samples')
export class PixelSampleController {
  constructor(private readonly pixelSampleService: PixelSampleService) {}

  @Get()
  findAll() {
    return this.pixelSampleService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.pixelSampleService.findOne(id);
  }

  @Post()
  create(@Body() createPixelSampleDto: CreatePixelSampleDto) {
    return this.pixelSampleService.create(createPixelSampleDto);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updatePixelSampleDto: UpdatePixelSampleDto,
  ) {
    return this.pixelSampleService.update(id, updatePixelSampleDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.pixelSampleService.remove(id);
  }
}
